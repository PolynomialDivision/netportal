-- The FreeRADIUS contract (docs/RADIUS_CONTRACT.md): everything the role radius may use is
-- in the schema radius, and nothing else. One view for the access decision, one function for the
-- reason of a refused certificate, three logging functions. sql/radius_grants.sql gives the
-- role USAGE on this schema, SELECT on its views and EXECUTE on its functions after every
-- migration run.
--
-- The logging functions are SECURITY DEFINER (they write as the schema owner; the role has no
-- table rights), take only text (what %{sql:...} expands, '' for a missing attribute), validate
-- it and never raise into FreeRADIUS. They wait at most 500 ms for a row lock (below the role's
-- lock_timeout 1 s and statement_timeout 2 s, so their EXCEPTION blocks, not a query_canceled,
-- end a blocked call). None of them is part of the access decision.

CREATE SCHEMA radius;

-- The access decision: a certificate serial (lowercase hex) that may log in now, with its
-- device and the VLAN of the device's policy.
CREATE VIEW radius.valid_cert AS
    SELECT c.serial, d.id::text AS device_id, p.vlan
    FROM credential c
    JOIN device d ON d.id = c.device_id
    JOIN policy p ON p.name = d.policy
    WHERE d.kind = 'cert' AND d.revoked_at IS NULL
      AND c.not_after > now()
      AND (c.retired_at IS NULL OR c.retired_at > now());

-- Why a serial does not get in: valid | unknown_cert | revoked | retired | expired.
CREATE FUNCTION radius.cert_status(p_serial text) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT coalesce((
        SELECT CASE
            WHEN d.kind <> 'cert' THEN 'unknown_cert'
            WHEN d.revoked_at IS NOT NULL THEN 'revoked'
            WHEN c.retired_at IS NOT NULL AND c.retired_at <= now() THEN 'retired'
            WHEN c.not_after <= now() THEN 'expired'
            ELSE 'valid' END
        FROM credential c JOIN device d ON d.id = c.device_id
        WHERE c.serial = lower(btrim(p_serial))), 'unknown_cert')
$$;

-- An Accept (post-auth): logs it with a fresh Class token, records the MAC identity and the
-- latest session (the Disconnect target), returns the token for reply:Class: 'np1:' and 22
-- base64url characters (NULL if nothing could be logged or the device is unknown).
CREATE FUNCTION radius.login(p_device_id text, p_serial text, p_calling text, p_called text,
                             p_nas_ip text, p_acct_session_id text, p_user_name text DEFAULT NULL)
RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp SET lock_timeout = '500ms' AS $$
DECLARE
    v_device  uuid;
    v_serial  text := CASE WHEN lower(btrim(p_serial)) ~ '^[0-9a-f]{1,64}$' THEN lower(btrim(p_serial)) END;
    v_mac     macaddr := np_mac(p_calling);
    v_nas     inet := np_inet(p_nas_ip);
    v_called  record;
    v_acct    text := nullif(left(btrim(p_acct_session_id), 253), '');
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
        INSERT INTO radius_auth (result, reason, device_id, serial, mac, nas_ip, bssid, ssid, class_token, acct_session_id)
        VALUES ('accept', 'ok', v_device, v_serial, v_mac, v_nas, v_called.bssid, v_called.ssid, v_token, v_acct);
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

-- A Reject (Post-Auth-Type REJECT) with its reason. With a serial the registry says why
-- (unknown_cert | revoked | retired | expired; a serial the registry would accept was refused by
-- the TLS layer: bad_chain, not attributed to the device); without one the hint from FreeRADIUS
-- (no_cert | not_eap | bad_chain | db_error, anything else: other). A reject with the same MAC,
-- reason, serial, NAS, BSSID and SSID as a row whose latest try is at most 60 s old adds to that
-- row (tries + 1, last_at now); a row spans at most an hour. A row another reject is updating
-- right now is skipped (a second row, never a wait).
CREATE FUNCTION radius.reject(p_serial text, p_calling text, p_called text, p_nas_ip text, p_reason_hint text)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp SET lock_timeout = '500ms' AS $$
DECLARE
    v_serial  text := CASE WHEN lower(btrim(p_serial)) ~ '^[0-9a-f]{1,64}$' THEN lower(btrim(p_serial)) END;
    v_mac     macaddr := np_mac(p_calling);
    v_nas     inet := np_inet(p_nas_ip);
    v_device  uuid;
    v_reason  text;
    v_called  record;
    v_id      bigint;
BEGIN
    v_called := np_called_station(p_called);
    IF v_serial IS NOT NULL THEN
        v_reason := radius.cert_status(v_serial);
        IF v_reason = 'valid' THEN
            v_reason := 'bad_chain';
        ELSIF v_reason <> 'unknown_cert' THEN
            SELECT device_id INTO v_device FROM credential WHERE serial = v_serial;
        END IF;
    ELSE
        v_reason := CASE WHEN p_reason_hint IN ('no_cert', 'not_eap', 'bad_chain', 'db_error')
                         THEN p_reason_hint ELSE 'other' END;
    END IF;
    -- two forms of one lookup, so each is an index condition ("mac = NULL" matches nothing)
    IF v_mac IS NOT NULL THEN
        SELECT id INTO v_id FROM radius_auth
         WHERE mac = v_mac AND at >= now() - interval '1 hour' AND result = 'reject' AND reason = v_reason
           AND coalesce(last_at, at) >= now() - interval '60 seconds'
           AND serial IS NOT DISTINCT FROM v_serial AND nas_ip IS NOT DISTINCT FROM v_nas
           AND bssid IS NOT DISTINCT FROM v_called.bssid AND ssid IS NOT DISTINCT FROM v_called.ssid
         ORDER BY at DESC LIMIT 1 FOR UPDATE SKIP LOCKED;
    ELSE
        SELECT id INTO v_id FROM radius_auth
         WHERE mac IS NULL AND at >= now() - interval '1 hour' AND result = 'reject' AND reason = v_reason
           AND coalesce(last_at, at) >= now() - interval '60 seconds'
           AND serial IS NOT DISTINCT FROM v_serial AND nas_ip IS NOT DISTINCT FROM v_nas
           AND bssid IS NOT DISTINCT FROM v_called.bssid AND ssid IS NOT DISTINCT FROM v_called.ssid
         ORDER BY at DESC LIMIT 1 FOR UPDATE SKIP LOCKED;
    END IF;
    IF v_id IS NOT NULL THEN
        UPDATE radius_auth SET tries = tries + 1, last_at = greatest(coalesce(last_at, at), now()) WHERE id = v_id;
    ELSE
        INSERT INTO radius_auth (result, reason, device_id, serial, mac, nas_ip, bssid, ssid)
        VALUES ('reject', v_reason, v_device, v_serial, v_mac, v_nas, v_called.bssid, v_called.ssid);
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'radius.reject: %', SQLERRM;
END $$;

-- An Accounting-Request (Start / Interim-Update / Stop / Accounting-On / Accounting-Off, by name
-- or number). Order-proof: every time is the packet's Event-Timestamp when plausible (at most 7
-- days back, never later than now), else its arrival; updated only moves forward; started is the
-- earliest a Start or an estimate (time minus Acct-Session-Time) gave; a Stop ends only its own
-- (nas_ip, acct_session_id), also when it arrived first; a retransmitted Stop keeps the first
-- stop time; counters only grow. The device: by the Class of its login (link 'class', kept once
-- found), else by the MAC's window ('mac_window'), else none; its MAC window grows with the
-- packet. A reused Acct-Session-Id (a Start newer than the Stop, or an Interim more than an
-- interval after it) opens the session again. Accounting-On/Off close the NAS's sessions that
-- began before it, at the On/Off or, for a session silent longer than 2 x its interval + 60 s, at
-- that point; they are remembered (radius_nas.reset_at), so a late Start/Interim from before ends
-- there. An Interim 30 s .. 1 day after the open session's latest update measures the interval:
-- the session keeps the smallest gap, the NAS follows when an estimate differs by more than 10 %.
CREATE FUNCTION radius.accounting(p_status text, p_acct_session_id text, p_class text, p_calling text,
                                  p_called text, p_nas_ip text, p_framed_ip text, p_session_time text,
                                  p_in_octets text, p_out_octets text, p_in_gigawords text,
                                  p_out_gigawords text, p_terminate_cause text, p_event_ts text)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp SET lock_timeout = '500ms' AS $$
DECLARE
    v_status  text := lower(btrim(p_status));
    v_nas     inet := np_inet(p_nas_ip);
    v_sid     text := nullif(btrim(p_acct_session_id), '');
    v_mac     macaddr := np_mac(p_calling);
    v_called  record;
    v_epoch   bigint := np_count(p_event_ts);
    v_at      timestamptz := now();
    v_link_at timestamptz;
    v_time    bigint := np_count(p_session_time);
    v_in      bigint;
    v_out     bigint;
    v_cause   text := nullif(left(btrim(p_terminate_cause), 64), '');
    v_class   text := btrim(p_class);
    v_device  uuid;
    v_link    text := 'none';
    v_old     record;
    v_found   boolean;
    v_reopen  boolean := false;
    v_gap     double precision;
    v_interim integer;
    v_est     integer;
    v_reset   record;
BEGIN
    IF v_nas IS NULL THEN
        RETURN;
    END IF;
    v_called := np_called_station(p_called);
    IF v_epoch IS NOT NULL AND v_epoch BETWEEN extract(epoch FROM now() - interval '7 days')
                                           AND extract(epoch FROM now() + interval '5 minutes') THEN
        v_at := least(to_timestamp(v_epoch), now());
    END IF;
    IF v_status IN ('accounting-on', 'accounting-off', '7', '8') THEN
        v_cause := CASE WHEN v_status IN ('accounting-on', '7') THEN 'NAS-Reboot' ELSE 'NAS-Request' END;
        UPDATE radius_acct
           SET stopped = greatest(coalesce(started, v_at),
                                  least(v_at, updated + make_interval(secs => 2 * coalesce(interim_s, 300) + 60))),
               terminate_cause = coalesce(terminate_cause, v_cause)
         WHERE nas_ip = v_nas AND stopped IS NULL AND coalesce(started, updated) <= v_at;
        BEGIN
            INSERT INTO radius_nas AS n (nas_ip, reset_at, reset_cause) VALUES (v_nas, v_at, v_cause)
            ON CONFLICT (nas_ip) DO UPDATE SET reset_at = EXCLUDED.reset_at, reset_cause = EXCLUDED.reset_cause
                WHERE n.reset_at IS NULL OR n.reset_at < EXCLUDED.reset_at;
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'radius.accounting: radius_nas: %', SQLERRM;
        END;
        RETURN;
    END IF;
    IF v_status NOT IN ('start', 'stop', 'interim-update', '1', '2', '3') OR v_sid IS NULL OR length(v_sid) > 253 THEN
        RETURN;
    END IF;
    v_status := CASE v_status WHEN '1' THEN 'start' WHEN '2' THEN 'stop' WHEN '3' THEN 'interim-update' ELSE v_status END;
    -- Acct-*-Gigawords: the 2^32 overflows of the 32-bit octet counters
    v_in := np_count(p_in_octets) + CASE WHEN np_count(p_in_gigawords) < 2147483648 THEN np_count(p_in_gigawords) ELSE 0 END * 4294967296;
    v_out := np_count(p_out_octets) + CASE WHEN np_count(p_out_gigawords) < 2147483648 THEN np_count(p_out_gigawords) ELSE 0 END * 4294967296;

    -- Class: FreeRADIUS prints octets as 0x<hex>; the token is ASCII
    IF v_class ~ '^0x([0-9a-fA-F]{2})+$' THEN
        BEGIN
            v_class := convert_from(decode(substr(v_class, 3), 'hex'), 'UTF8');
        EXCEPTION WHEN OTHERS THEN
            v_class := NULL;
        END;
    END IF;
    IF v_class ~ '^np1:[A-Za-z0-9_-]{22}$' THEN
        SELECT device_id INTO v_device FROM radius_auth WHERE class_token = v_class AND result = 'accept';
        IF v_device IS NOT NULL THEN
            v_link := 'class';
        END IF;
    END IF;
    SELECT link, device_id, updated, stopped, interim_s INTO v_old
      FROM radius_acct WHERE nas_ip = v_nas AND acct_session_id = v_sid;
    v_found := FOUND;
    IF v_link = 'none' AND v_found AND v_old.link <> 'none' THEN
        v_link := v_old.link;
        v_device := v_old.device_id;
    END IF;
    IF v_link = 'none' AND v_mac IS NOT NULL THEN
        -- a packet arriving now is looked up at its arrival (the AP's clock may lag the login's),
        -- a late one at its own time
        v_link_at := CASE WHEN abs(extract(epoch FROM v_at - now())) < 300 THEN now() ELSE v_at END;
        v_device := np_device_for_mac(v_mac, v_link_at);
        IF v_device IS NOT NULL THEN
            v_link := 'mac_window';
        END IF;
    END IF;
    IF v_found AND v_old.stopped IS NOT NULL AND (
           (v_status = 'start' AND v_at > v_old.stopped)
           OR (v_status = 'interim-update'
               AND v_at > v_old.stopped + make_interval(secs => greatest(coalesce(v_old.interim_s, 300), 60)))) THEN
        v_reopen := true;
    END IF;
    IF v_status = 'interim-update' AND v_found AND v_old.stopped IS NULL AND v_at > v_old.updated THEN
        v_gap := extract(epoch FROM v_at - v_old.updated);
        IF v_gap BETWEEN 30 AND 86400 THEN
            v_interim := round(v_gap)::integer;
        END IF;
    END IF;

    INSERT INTO radius_acct AS a (nas_ip, acct_session_id, device_id, link, mac, bssid, ssid, framed_ip, started,
                                  updated, stopped, session_time_s, input_octets, output_octets, terminate_cause,
                                  interim_s)
    VALUES (v_nas, v_sid, v_device, v_link, v_mac, v_called.bssid, v_called.ssid, np_inet(p_framed_ip),
            CASE WHEN v_status = 'start' THEN v_at ELSE v_at - make_interval(secs => coalesce(v_time, 0)) END,
            v_at, CASE WHEN v_status = 'stop' THEN v_at END, v_time, v_in, v_out,
            CASE WHEN v_status = 'stop' THEN v_cause END, v_interim)
    ON CONFLICT (nas_ip, acct_session_id) DO UPDATE SET
        device_id = EXCLUDED.device_id,
        link = EXCLUDED.link,
        mac = coalesce(EXCLUDED.mac, a.mac),
        bssid = coalesce(EXCLUDED.bssid, a.bssid),
        ssid = coalesce(EXCLUDED.ssid, a.ssid),
        framed_ip = coalesce(EXCLUDED.framed_ip, a.framed_ip),
        started = CASE WHEN v_reopen THEN EXCLUDED.started ELSE least(a.started, EXCLUDED.started) END,
        updated = greatest(a.updated, EXCLUDED.updated),
        stopped = CASE WHEN v_reopen THEN NULL
                       WHEN v_status = 'stop' THEN least(a.stopped, EXCLUDED.stopped) ELSE a.stopped END,
        session_time_s = CASE WHEN v_reopen THEN EXCLUDED.session_time_s
                              ELSE greatest(a.session_time_s, EXCLUDED.session_time_s) END,
        input_octets = CASE WHEN v_reopen THEN EXCLUDED.input_octets ELSE greatest(a.input_octets, EXCLUDED.input_octets) END,
        output_octets = CASE WHEN v_reopen THEN EXCLUDED.output_octets
                             ELSE greatest(a.output_octets, EXCLUDED.output_octets) END,
        terminate_cause = CASE WHEN v_reopen THEN NULL
                               WHEN v_status = 'stop' THEN coalesce(EXCLUDED.terminate_cause, a.terminate_cause)
                               ELSE a.terminate_cause END,
        interim_s = CASE WHEN v_reopen THEN NULL ELSE least(a.interim_s, EXCLUDED.interim_s) END;

    IF v_status <> 'stop' THEN
        -- from before the NAS's latest Accounting-On/Off (arrived after it): ended there
        SELECT reset_at, reset_cause INTO v_reset FROM radius_nas WHERE nas_ip = v_nas;
        IF FOUND AND v_reset.reset_at IS NOT NULL AND v_at < v_reset.reset_at THEN
            UPDATE radius_acct
               SET stopped = greatest(coalesce(started, v_reset.reset_at), v_reset.reset_at),
                   terminate_cause = coalesce(terminate_cause, v_reset.reset_cause)
             WHERE nas_ip = v_nas AND acct_session_id = v_sid AND stopped IS NULL AND updated <= v_reset.reset_at;
        END IF;
    END IF;
    IF v_interim IS NOT NULL THEN
        v_est := least(v_old.interim_s, v_interim);
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM radius_nas WHERE nas_ip = v_nas AND interim_s IS NOT NULL
                                                      AND abs(interim_s - v_est) <= interim_s * 0.1) THEN
                INSERT INTO radius_nas AS n (nas_ip, interim_s, interim_at) VALUES (v_nas, v_est, v_at)
                ON CONFLICT (nas_ip) DO UPDATE SET interim_s = EXCLUDED.interim_s, interim_at = EXCLUDED.interim_at;
            END IF;
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'radius.accounting: radius_nas: %', SQLERRM;
        END;
    END IF;

    IF v_device IS NOT NULL AND v_mac IS NOT NULL THEN
        INSERT INTO device_mac (device_id, mac, first_seen, last_seen, auth_count, randomized)
        VALUES (v_device, v_mac, v_at, v_at, 0, (v_mac & '02:00:00:00:00:00') = '02:00:00:00:00:00')
        ON CONFLICT (device_id, mac) DO UPDATE SET last_seen = greatest(device_mac.last_seen, EXCLUDED.last_seen);
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'radius.accounting: %', SQLERRM;
END $$;
