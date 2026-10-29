-- The owner's review of 2026-10-29 (docs/PARITY.md, deliberate deviations): portal sessions
-- on the server, and what the Disconnect reconciliation needs.

-- --- portal sessions -------------------------------------------------------------------------------

-- One row per portal login. The session cookie (encrypted and signed) carries the session's id;
-- only its SHA-256 is stored. A request is logged in only while its row exists, is not ended and
-- is younger than the absolute limit (12 h; the 8 h idle limit is the cookie's own timestamp).
-- A logout ends its own row; "log out everywhere", an offboarding and the loss of the admin
-- right end every row of the person, so copies of the cookie stop working too. Ended and
-- expired rows are deleted by the retention job (registry::prune) and at the person's next
-- login.
CREATE TABLE web_session (
    id_hash     text PRIMARY KEY CHECK (id_hash ~ '^[0-9a-f]{64}$'),
    sub         text NOT NULL REFERENCES person(sub) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    ended_at    timestamptz,
    CHECK (ended_at IS NULL OR ended_at >= created_at)
);
CREATE INDEX web_session_sub ON web_session (sub);
CREATE INDEX web_session_created ON web_session (created_at);

-- The epoch of migration 0003 is replaced by the rows above. The column stays (unused, default
-- 0): migrations only add, so an image from before this one still runs on a migrated database
-- after a rollback. A later migration may drop it once no rollback past 0005 is wanted.

-- --- the Disconnect reconciliation -----------------------------------------------------------------

-- The VLAN an Accept assigned (radius.login's new argument p_vlan, FreeRADIUS's decision): a
-- session whose login put it into another VLAN than the device's policy has now is cut again.
ALTER TABLE radius_auth ADD COLUMN vlan integer CHECK (vlan BETWEEN 1 AND 4094);
ALTER TABLE radius_auth ADD CONSTRAINT radius_auth_vlan_on_accepts CHECK (result = 'accept' OR vlan IS NULL);

-- When the registry first heard of an accounting session, on its own clock (started and updated
-- are the access point's Event-Timestamps): the session's login is the device's latest Accept
-- with that MAC before it.
ALTER TABLE radius_acct ADD COLUMN opened_at timestamptz NOT NULL DEFAULT now();

-- Accounting sessions the reconciliation (netportal offboard --every, NETPORTAL_DISCONNECT_RECHECK_S)
-- found still live although their device is revoked, their certificate no longer valid or their
-- VLAN no longer the policy's: its Disconnect-Requests, with backoff and a cap. A session is
-- settled by an ACK ('ack'), by a NAK with Error-Cause 503 Session-Context-Not-Found
-- ('not_found': the access point has no such session; never asked again), when it stops being
-- live ('stale': a Stop, or no Start/Interim-Update for two accounting intervals) or after the
-- last try ('given_up'). A settled session the access point still reports later (an
-- Interim-Update after the ACK) is tried again until the cap.
CREATE TABLE disconnect_recheck (
    nas_ip           inet NOT NULL,
    acct_session_id  text NOT NULL,
    device_id        uuid NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    reason           text NOT NULL CHECK (reason IN ('revoked', 'credential', 'vlan')),
    found_at         timestamptz NOT NULL DEFAULT now(),
    tries            integer NOT NULL DEFAULT 0 CHECK (tries >= 0),
    last_at          timestamptz,
    last_result      text CHECK (last_result IN ('ack', 'not_found', 'nak', 'timeout', 'error', 'skipped')),
    next_at          timestamptz NOT NULL DEFAULT now(),
    settled          text CHECK (settled IN ('ack', 'not_found', 'stale', 'given_up')),
    settled_at       timestamptz,
    CHECK ((settled IS NULL) = (settled_at IS NULL)),
    PRIMARY KEY (nas_ip, acct_session_id),
    FOREIGN KEY (nas_ip, acct_session_id) REFERENCES radius_acct (nas_ip, acct_session_id) ON DELETE CASCADE
);
CREATE INDEX disconnect_recheck_device ON disconnect_recheck (device_id);

-- A stopped accounting session that radius.accounting opens again (the same Acct-Session-Id at
-- the same NAS: v_reopen in 0002) is a new session: it is judged by its own login (opened_at
-- now) and starts without the old one's reconciliation state (an old "not_found" must not keep
-- it from ever being cut).
CREATE FUNCTION np_radius_acct_reopened() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_WHEN = 'BEFORE' THEN
        NEW.opened_at := now();
        RETURN NEW;
    END IF;
    DELETE FROM disconnect_recheck WHERE nas_ip = NEW.nas_ip AND acct_session_id = NEW.acct_session_id;
    RETURN NULL;
END
$$;
CREATE TRIGGER radius_acct_reopened_opened_at BEFORE UPDATE ON radius_acct FOR EACH ROW
    WHEN (OLD.stopped IS NOT NULL AND NEW.stopped IS NULL) EXECUTE FUNCTION np_radius_acct_reopened();
CREATE TRIGGER radius_acct_reopened_recheck AFTER UPDATE ON radius_acct FOR EACH ROW
    WHEN (OLD.stopped IS NOT NULL AND NEW.stopped IS NULL) EXECUTE FUNCTION np_radius_acct_reopened();

-- radius.login with the Accept's VLAN (an 8th argument, '' or missing: not recorded). Otherwise
-- unchanged from 0002.
DROP FUNCTION radius.login(text, text, text, text, text, text, text);

CREATE FUNCTION radius.login(p_device_id text, p_serial text, p_calling text, p_called text,
                             p_nas_ip text, p_acct_session_id text, p_user_name text DEFAULT NULL,
                             p_vlan text DEFAULT NULL)
RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp SET lock_timeout = '500ms' AS $$
DECLARE
    v_device  uuid;
    v_serial  text := CASE WHEN lower(btrim(p_serial)) ~ '^[0-9a-f]{1,64}$' THEN lower(btrim(p_serial)) END;
    v_mac     macaddr := np_mac(p_calling);
    v_nas     inet := np_inet(p_nas_ip);
    v_called  record;
    v_acct    text := nullif(left(btrim(p_acct_session_id), 253), '');
    -- nested CASE: the cast only after the pattern matched (an error here would escape the
    -- EXCEPTION clause below, which does not cover the declarations)
    v_vlan    integer := CASE WHEN btrim(p_vlan) ~ '^[0-9]{1,4}$' THEN
                              CASE WHEN btrim(p_vlan)::integer BETWEEN 1 AND 4094 THEN btrim(p_vlan)::integer END
                          END;
    v_token   text;
BEGIN
    IF btrim(p_device_id) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        SELECT id INTO v_device FROM device WHERE id = btrim(p_device_id)::uuid;
    END IF;
    IF v_device IS NULL THEN
        RETURN NULL;
    END IF;
    v_called := np_called_station(p_called);
    -- 22 base64url characters of two random v4 UUIDs (about 126 random bits)
    v_token := 'np1:' || left(translate(encode(uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()), 'base64'),
                                        '+/', '-_'), 22);
    BEGIN
        INSERT INTO radius_auth (result, reason, device_id, serial, mac, nas_ip, bssid, ssid, class_token, acct_session_id,
                                 vlan)
        VALUES ('accept', 'ok', v_device, v_serial, v_mac, v_nas, v_called.bssid, v_called.ssid, v_token, v_acct, v_vlan);
    EXCEPTION WHEN OTHERS THEN
        RAISE WARNING 'radius.login: radius_auth: %', SQLERRM;
        v_token := NULL;
    END;
    IF v_mac IS NOT NULL THEN
        BEGIN
            INSERT INTO device_mac (device_id, mac, first_seen, last_seen, auth_count, randomized)
            VALUES (v_device, v_mac, now(), now(), 1, (v_mac & '02:00:00:00:00:00') = '02:00:00:00:00:00')
            ON CONFLICT (device_id, mac) DO UPDATE
                SET last_seen = greatest(device_mac.last_seen, now()), auth_count = device_mac.auth_count + 1;
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'radius.login: device_mac: %', SQLERRM;
        END;
    END IF;
    IF v_nas IS NOT NULL THEN
        BEGIN
            INSERT INTO radius_session (device_id, nas_ip, calling_station, user_name, first_seen, updated)
            VALUES (v_device, v_nas, coalesce(left(p_calling, 64), ''), coalesce(left(p_user_name, 253), ''),
                    now(), now())
            ON CONFLICT (device_id) DO UPDATE
                SET nas_ip = EXCLUDED.nas_ip, calling_station = EXCLUDED.calling_station,
                    user_name = EXCLUDED.user_name, updated = now(),
                    first_seen = CASE WHEN radius_session.calling_station IS DISTINCT FROM EXCLUDED.calling_station
                                      THEN now() ELSE radius_session.first_seen END;
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'radius.login: radius_session: %', SQLERRM;
        END;
    END IF;
    RETURN v_token;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'radius.login: %', SQLERRM;
    RETURN NULL;
END $$;
