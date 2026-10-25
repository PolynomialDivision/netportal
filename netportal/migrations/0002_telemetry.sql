-- Migration 0002: telemetry v2 (docs/TELEMETRY.md). Device identities over time (device_mac),
-- every RADIUS decision (radius_auth) and accounting session (radius_acct), UniFi's client
-- events (connection_event), daily rollups (device_day, ap_day), infrastructure incidents, the
-- extended job table, and the functions FreeRADIUS writes through. Applied once, inside the
-- runner's transaction; additive only (the previous release keeps working on this schema).

-- --- tables -----------------------------------------------------------------------------------

-- MAC identities: when a device's certificate logged in with which MAC (one row per device+MAC).
-- A window is [first_seen, window_end] (view device_mac_window, below: 15 min grace, the current
-- one up to 12 h 15 min): data of the MAC in it belongs to the device, outside it to nobody.
CREATE TABLE device_mac (
    device_id   uuid NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    mac         macaddr NOT NULL,
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,         -- last login, accounting or UniFi event with it
    auth_count  integer NOT NULL DEFAULT 0,
    randomized  boolean NOT NULL,             -- locally administered bit
    PRIMARY KEY (device_id, mac)
);
CREATE INDEX device_mac_mac ON device_mac (mac, first_seen);

-- Every RADIUS decision with its reason (accepts and rejects). Repeated rejects are one row
-- (radius_reject): count tries from at to last_at.
CREATE TABLE radius_auth (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),   -- the (first) decision
    count       integer NOT NULL DEFAULT 1,           -- decisions in this row (rejects: repeats)
    last_at     timestamptz,                          -- the latest repeat (NULL: none, count 1)
    result      text NOT NULL CHECK (result IN ('accept', 'reject')),
    reason      text NOT NULL,                -- ok | unknown_cert | revoked | expired | retired |
                                              -- no_cert | bad_chain | not_eap | db_error | other
    device_id   uuid REFERENCES device(id) ON DELETE SET NULL,
    serial      text,
    mac         macaddr,
    nas_ip      inet,
    bssid       macaddr,                      -- from Called-Station-Id "<BSSID>:<SSID>"
    ssid        text,
    class_token text UNIQUE,                  -- the Class sent in the Accept (random, opaque)
    acct_session_id text                      -- if the Access-Request carries one
);
CREATE INDEX radius_auth_device ON radius_auth (device_id, at);
CREATE INDEX radius_auth_at ON radius_auth (at);
-- Rejects without a known serial are found by the device's MACs (registry.auth_events); and
-- radius_reject finds the row a repeat adds to by it (MAC, then the last hour).
CREATE INDEX radius_auth_mac ON radius_auth (mac, at);

-- RADIUS accounting sessions (one row per NAS session, updated by Interim and Stop).
CREATE TABLE radius_acct (
    nas_ip          inet NOT NULL,
    acct_session_id text NOT NULL,
    device_id       uuid REFERENCES device(id) ON DELETE SET NULL,  -- via class_token, else MAC window
    link            text NOT NULL CHECK (link IN ('class', 'mac_window', 'none')),
    mac             macaddr,
    bssid           macaddr,
    ssid            text,
    framed_ip       inet,
    started         timestamptz,
    updated         timestamptz NOT NULL,
    stopped         timestamptz,
    session_time_s  bigint,
    input_octets    bigint,                   -- from the AP's view (device upload)
    output_octets   bigint,                   -- device download
    terminate_cause text,
    PRIMARY KEY (nas_ip, acct_session_id)
);
CREATE INDEX radius_acct_device ON radius_acct (device_id, updated);
CREATE INDEX radius_acct_updated ON radius_acct (updated);

-- Connection events from UniFi's system log (via unpoller -> Loki -> collector) and derived ones.
CREATE TABLE connection_event (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at          timestamptz NOT NULL,
    mac         macaddr NOT NULL,
    device_id   uuid REFERENCES device(id) ON DELETE SET NULL,   -- resolved by window at ingest
    kind        text NOT NULL CHECK (kind IN ('connected', 'disconnected', 'roamed', 'other')),
    source      text NOT NULL,                -- unifi_syslog
    ap_mac      macaddr,
    ap_name     text,
    from_ap_mac macaddr,
    from_ap_name text,
    ssid        text,
    radio       text,
    channel     integer,
    rssi        integer,
    duration_s  bigint,
    rx_bytes    bigint,
    tx_bytes    bigint,
    detail      jsonb NOT NULL DEFAULT '{}',  -- the raw fields we did not map
    dedup_key   text NOT NULL UNIQUE          -- source + event key (idempotent ingest)
);
CREATE INDEX connection_event_device ON connection_event (device_id, at);
CREATE INDEX connection_event_mac ON connection_event (mac, at);
CREATE INDEX connection_event_at ON connection_event (at);

-- Nightly per-device rollups (Europe/Berlin days), from Prometheus, idempotent per (device, day).
CREATE TABLE device_day (
    device_id       uuid NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    day             date NOT NULL,
    online_s        integer,                  -- seconds associated (fresh data only)
    stale_s         integer,                  -- seconds without fresh UniFi data
    signal_avg_dbm  real, signal_p10_dbm real,
    snr_avg_db      real,
    health_avg      real, health_min real,
    retry_ratio_avg real,
    rx_bytes        bigint, tx_bytes bigint,  -- device's view
    link_rx_avg_bps real,
    roams           integer, reconnects integer,
    disconnects     integer,                  -- from connection_event / accounting when present
    aps             jsonb NOT NULL DEFAULT '{}',   -- {ap_mac: seconds}
    bands           jsonb NOT NULL DEFAULT '{}',   -- {"2.4"|"5"|"6": seconds}
    macs            integer,                  -- distinct MACs that day
    auth_ok         integer, auth_failed integer,
    computed        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, day)
);

-- Per-AP daily rollups (by AP MAC; name as of that day).
CREATE TABLE ap_day (
    ap_mac          macaddr NOT NULL,
    day             date NOT NULL,
    ap_name         text,
    clients_avg real, clients_max integer,
    channel_util_avg jsonb NOT NULL DEFAULT '{}',  -- {radio: ratio}
    weak_client_share real,                   -- share of client-minutes below -75 dBm
    restarts integer, down_s integer,
    computed        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ap_mac, day)
);

-- Infrastructure incidents derived from monitoring (stored: survive Prometheus retention and
-- rule changes). Open incidents have ended NULL.
CREATE TABLE incident (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind        text NOT NULL,                -- internet_down | internet_degraded | router_down |
                                              -- dns_down | ap_down | ap_restarted | switch_down |
                                              -- switch_port_down | unifi_data_stale | radius_down
    subject     text NOT NULL DEFAULT '',     -- AP MAC, switch name, port, '' for house-wide
    subject_name text,
    started     timestamptz NOT NULL,
    ended       timestamptz,
    basis       text NOT NULL CHECK (basis IN ('measured', 'inferred')),
    detail      jsonb NOT NULL DEFAULT '{}',
    UNIQUE (kind, subject, started)
);
CREATE INDEX incident_time ON incident (started, ended);
-- At most one open incident per kind and subject (registry.open_incident relies on it).
CREATE UNIQUE INDEX incident_open ON incident (kind, subject) WHERE ended IS NULL;

-- Jobs: extended (name PK kept). A job the collector runs has no success before its first run.
ALTER TABLE job ADD COLUMN last_attempt timestamptz, ADD COLUMN last_error text,
    ADD COLUMN duration_s real, ADD COLUMN cursor jsonb NOT NULL DEFAULT '{}';
ALTER TABLE job ALTER COLUMN last_success DROP NOT NULL;

-- --- helpers (input normalisation; never raise) -----------------------------------------------

-- The one MAC normaliser (registry.normalise_mac is its Python twin, tested against it):
-- AA-BB-CC-DD-EE-FF (what access points send), aa:bb:cc:dd:ee:ff or 12 bare hex digits, any
-- case, surrounding whitespace ignored; anything else (mixed separators, dots, junk) -> NULL.
CREATE FUNCTION np_mac(raw text) RETURNS macaddr
LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = public, pg_temp AS $$
    SELECT CASE
        WHEN m ~ '^[0-9a-f]{12}$' THEN m::macaddr
        WHEN m ~ '^[0-9a-f]{2}([-:])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$' THEN m::macaddr
    END
    FROM (SELECT lower(btrim(raw, E' \t\n\r\f\v')) AS m) s
$$;

-- A host address (v4 or v6, no netmask) or NULL.
CREATE FUNCTION np_inet(raw text) RETURNS inet
LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = public, pg_temp AS $$
DECLARE
    v inet;
BEGIN
    IF raw IS NULL OR length(raw) > 64 OR btrim(raw) !~ '^[0-9a-fA-F:.]+$' THEN
        RETURN NULL;
    END IF;
    v := btrim(raw)::inet;
    RETURN CASE WHEN masklen(v) = CASE family(v) WHEN 4 THEN 32 ELSE 128 END THEN v END;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END $$;

-- A non-negative integer from a RADIUS integer attribute (decimal text) or NULL.
CREATE FUNCTION np_count(raw text) RETURNS bigint
LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = public, pg_temp AS $$
    SELECT CASE WHEN btrim(raw) ~ '^[0-9]{1,18}$' THEN btrim(raw)::bigint END
$$;

-- Called-Station-Id "<BSSID>:<SSID>" (hostapd: AA-BB-CC-DD-EE-FF:Name) -> (bssid, ssid); a bare
-- BSSID gives no SSID; anything else gives (NULL, NULL).
CREATE FUNCTION np_called_station(raw text, OUT bssid macaddr, OUT ssid text)
LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = public, pg_temp AS $$
DECLARE
    m text[];
BEGIN
    m := regexp_match(coalesce(btrim(raw), ''), '^([0-9A-Fa-f]{2}(?:[-:]?[0-9A-Fa-f]{2}){5})(?::(.*))?$');
    IF m IS NOT NULL THEN
        bssid := np_mac(m[1]);
        IF bssid IS NOT NULL THEN
            ssid := nullif(left(m[2], 64), '');
        END IF;
    END IF;
END $$;

-- The windows, the one rule everything uses (np_device_for_mac, registry.device_windows,
-- window_conflicts, auth_events; telemetry reads window_end from device_windows):
--   [first_seen, window_end], window_end = last_seen + 15 min (registry.WINDOW_GRACE: data until
--   the device leaves), except for the device's CURRENT window (its MAC with the newest
--   last_seen, device not revoked): last_seen + 12 h 15 min (registry.CURRENT_WINDOW), but not
--   beyond now. A device logs in again at least every 12 h (Session-Timeout, RADIUS-Request),
--   and accounting (Interim every 300 s) moves last_seen meanwhile; until either arrives the
--   last login is all the registry knows, and the device may still be there. 12 h is the stack's
--   RADIUS_SESSION_TIMEOUT (43200): change both together.
CREATE VIEW device_mac_window AS
    SELECT w.device_id, w.mac, w.first_seen, w.last_seen, w.auth_count, w.randomized, w.current,
           CASE WHEN w.current
                THEN least(w.last_seen + interval '12 hours 15 minutes',
                           greatest(now(), w.last_seen + interval '15 minutes'))
                ELSE w.last_seen + interval '15 minutes' END AS window_end
    FROM (SELECT m.*, d.owner, (d.revoked IS NULL AND m.last_seen = max(m.last_seen) OVER (PARTITION BY m.device_id))
                 AS current
          FROM device_mac m JOIN device d ON d.id = m.device_id) w;

-- The device a MAC belonged to at a time: the windows (above) that contain it; NULL when
-- none, or when devices of more than one owner claim it then (a conflict: the data belongs to
-- nobody). Several devices of the same owner (a re-enrolment): the one seen last.
-- registry.device_for_mac calls this, so there is one definition.
CREATE FUNCTION np_device_for_mac(p_mac macaddr, p_at timestamptz) RETURNS uuid
LANGUAGE sql STABLE SET search_path = public, pg_temp AS $$
    SELECT CASE WHEN count(DISTINCT d.owner) = 1
                THEN (array_agg(w.device_id ORDER BY w.last_seen DESC))[1] END
    FROM device_mac_window w JOIN device d ON d.id = w.device_id
    WHERE w.mac = p_mac AND p_at >= w.first_seen AND p_at <= w.window_end
$$;

-- --- the functions FreeRADIUS calls (role radius: EXECUTE on these and SELECT radius_cert) ---
-- SECURITY DEFINER: they write as the schema owner, the radius role has no table rights. Every
-- argument is text (what %{sql:...} expands, '' for a missing attribute) and is validated here;
-- bad input gives NULL / nothing, never an error into FreeRADIUS. None of them is part of the
-- access decision (that is the view radius_cert): their result never changes an Accept or a
-- Reject (radius/sites/default), and FreeRADIUS calls them through its own small connection pool
-- (radius/mods/sql_log), never the decision's.
-- The logging functions wait at most 500 ms for a row lock (lock_timeout, below the role's 1 s):
-- a lock held elsewhere (the collector updating device_mac, a second login of the same device)
-- then raises lock_not_available, which their EXCEPTION blocks catch, so the call returns well
-- inside the role's statement_timeout (2 s). That timeout raises query_canceled, which no
-- EXCEPTION WHEN OTHERS catches: it would fail the whole call, so it must not be the one that hits.

-- Why a serial does not get in: valid | unknown_cert | revoked | retired | expired.
CREATE FUNCTION radius_cert_status(p_serial text) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT coalesce((
        SELECT CASE
            WHEN d.kind <> 'cert' THEN 'unknown_cert'
            WHEN d.revoked IS NOT NULL THEN 'revoked'
            WHEN c.retired_after IS NOT NULL AND c.retired_after <= now() THEN 'retired'
            WHEN c.not_after <= now() THEN 'expired'
            ELSE 'valid' END
        FROM credential c JOIN device d ON d.id = c.device_id
        WHERE c.serial = lower(btrim(p_serial))), 'unknown_cert')
$$;

-- An Accept (post-auth): logs it with a fresh Class token, records the MAC identity and the
-- latest session (the Disconnect target, exactly as the former post-auth INSERT did, incl.
-- first_seen), returns the token for reply:Class (NULL if nothing could be logged).
-- p_user_name: the outer User-Name, kept in radius_session for the Disconnect-Request.
CREATE FUNCTION radius_login(p_device_id text, p_serial text, p_calling text, p_called text,
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
    -- 'np1:' + 22 base64url characters (126 random bits from two v4 UUIDs).
    v_token := 'np1:' || left(translate(encode(decode(
        replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''), 'hex'), 'base64'), '+/', '-_'), 22);
    BEGIN
        INSERT INTO radius_auth (result, reason, device_id, serial, mac, nas_ip, bssid, ssid, class_token, acct_session_id)
        VALUES ('accept', 'ok', v_device, v_serial, v_mac, v_nas, v_called.bssid, v_called.ssid, v_token, v_acct);
    EXCEPTION WHEN OTHERS THEN
        RAISE WARNING 'radius_login: radius_auth: %', SQLERRM;
        v_token := NULL;
    END;
    IF v_mac IS NOT NULL THEN
        BEGIN
            INSERT INTO device_mac (device_id, mac, first_seen, last_seen, auth_count, randomized)
            VALUES (v_device, v_mac, now(), now(), 1, (v_mac & '02:00:00:00:00:00') = '02:00:00:00:00:00')
            ON CONFLICT (device_id, mac) DO UPDATE
                SET last_seen = greatest(device_mac.last_seen, now()), auth_count = device_mac.auth_count + 1;
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'radius_login: device_mac: %', SQLERRM;
        END;
    END IF;
    IF v_nas IS NOT NULL THEN
        BEGIN
            INSERT INTO radius_session (device_id, nas_ip, calling_station, user_name, updated, first_seen)
            VALUES (v_device, host(v_nas), coalesce(left(p_calling, 64), ''), coalesce(left(p_user_name, 253), ''),
                    now(), now())
            ON CONFLICT (device_id) DO UPDATE
                SET nas_ip = EXCLUDED.nas_ip, calling_station = EXCLUDED.calling_station,
                    user_name = EXCLUDED.user_name, updated = now(),
                    first_seen = CASE WHEN radius_session.calling_station IS DISTINCT FROM EXCLUDED.calling_station
                                      THEN now() ELSE radius_session.first_seen END;
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'radius_login: radius_session: %', SQLERRM;
        END;
    END IF;
    RETURN v_token;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'radius_login: %', SQLERRM;
    RETURN NULL;
END $$;

-- A Reject (Post-Auth-Type REJECT): logs it with its reason. With a serial the registry says
-- why (unknown_cert | revoked | retired | expired; a serial the registry would accept was
-- refused by the TLS layer: bad_chain, not attributed to the device since the certificate was
-- not proven to be ours); without one the hint from FreeRADIUS (no_cert | not_eap | other).
-- Repeats are aggregated: anyone in radio range can loop EAP, and each try is a reject. A reject
-- with the same MAC, reason, serial, NAS, BSSID and SSID as a row whose latest try (last_at,
-- else at) is at most 60 s old adds to that row (count + 1, last_at now) instead of a new row; a
-- row spans at most an hour (then the next try starts a new one), so a flood of one sender
-- costs about a row an hour and time ranges by `at` stay exact to the hour
-- (registry.REJECT_REPEAT, REJECT_SPAN). The lookup is an index scan of radius_auth_mac (the
-- MAC's last hour); a row another reject is updating right now is skipped (a second row, never
-- a wait).
CREATE FUNCTION radius_reject(p_serial text, p_calling text, p_called text, p_nas_ip text, p_reason_hint text)
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
        v_reason := radius_cert_status(v_serial);
        IF v_reason = 'valid' THEN
            v_reason := 'bad_chain';
        ELSIF v_reason <> 'unknown_cert' THEN
            SELECT device_id INTO v_device FROM credential WHERE serial = v_serial;
        END IF;
    ELSE
        v_reason := CASE WHEN p_reason_hint IN ('no_cert', 'not_eap', 'bad_chain', 'db_error')
                         THEN p_reason_hint ELSE 'other' END;
    END IF;
    -- Two forms of one lookup, so each is an index condition ("mac = NULL" matches nothing).
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
        UPDATE radius_auth SET count = count + 1, last_at = greatest(coalesce(last_at, at), now()) WHERE id = v_id;
    ELSE
        INSERT INTO radius_auth (result, reason, device_id, serial, mac, nas_ip, bssid, ssid)
        VALUES ('reject', v_reason, v_device, v_serial, v_mac, v_nas, v_called.bssid, v_called.ssid);
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'radius_reject: %', SQLERRM;
END $$;

-- An Accounting-Request: Start / Interim-Update / Stop upsert the session (nas_ip,
-- acct_session_id); counters only grow (reordered packets), a Stop sets stopped and the cause.
-- The device: by the Class token of its login (link 'class', kept once found), else by the
-- MAC's window at that time ('mac_window'), else none. The device's MAC window is extended to
-- the packet. Accounting-On / -Off (the NAS restarted or stops): its open sessions end.
-- p_event_ts: Event-Timestamp as epoch seconds (%{integer:Event-Timestamp}); used when it is
-- plausible (within 7 days back, 5 minutes ahead), else the time of arrival.
CREATE FUNCTION radius_accounting(p_status text, p_acct_session_id text, p_class text, p_calling text,
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
BEGIN
    IF v_nas IS NULL THEN
        RETURN;
    END IF;
    v_called := np_called_station(p_called);
    IF v_epoch IS NOT NULL AND v_epoch BETWEEN extract(epoch FROM now() - interval '7 days')
                                           AND extract(epoch FROM now() + interval '5 minutes') THEN
        v_at := to_timestamp(v_epoch);
    END IF;
    IF v_status IN ('accounting-on', 'accounting-off', '7', '8') THEN
        UPDATE radius_acct
           SET stopped = greatest(coalesce(started, v_at), v_at), updated = greatest(updated, v_at),
               terminate_cause = coalesce(terminate_cause,
                                          CASE WHEN v_status IN ('accounting-on', '7') THEN 'NAS-Reboot' ELSE 'NAS-Request' END)
         WHERE nas_ip = v_nas AND stopped IS NULL;
        RETURN;
    END IF;
    IF v_status NOT IN ('start', 'stop', 'interim-update', '1', '2', '3') OR v_sid IS NULL OR length(v_sid) > 253 THEN
        RETURN;
    END IF;
    v_status := CASE v_status WHEN '1' THEN 'start' WHEN '2' THEN 'stop' WHEN '3' THEN 'interim-update' ELSE v_status END;
    -- Acct-*-Gigawords: the 2^32 overflows of the 32-bit octet counters.
    v_in := np_count(p_in_octets) + CASE WHEN np_count(p_in_gigawords) < 2147483648 THEN np_count(p_in_gigawords) ELSE 0 END * 4294967296;
    v_out := np_count(p_out_octets) + CASE WHEN np_count(p_out_gigawords) < 2147483648 THEN np_count(p_out_gigawords) ELSE 0 END * 4294967296;

    -- Class: FreeRADIUS prints octets as 0x<hex>; the token is ASCII.
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
    SELECT link, device_id INTO v_old FROM radius_acct WHERE nas_ip = v_nas AND acct_session_id = v_sid;
    IF v_link = 'none' AND FOUND AND v_old.link <> 'none' THEN
        v_link := v_old.link;
        v_device := v_old.device_id;
    END IF;
    IF v_link = 'none' AND v_mac IS NOT NULL THEN
        -- A packet that arrives now is looked up at its arrival (the AP's clock may be a little
        -- behind the login's); a late one at its own time.
        v_link_at := CASE WHEN abs(extract(epoch FROM v_at - now())) < 300 THEN now() ELSE v_at END;
        v_device := np_device_for_mac(v_mac, v_link_at);
        IF v_device IS NOT NULL THEN
            v_link := 'mac_window';
        END IF;
    END IF;

    INSERT INTO radius_acct AS a (nas_ip, acct_session_id, device_id, link, mac, bssid, ssid, framed_ip, started,
                                  updated, stopped, session_time_s, input_octets, output_octets, terminate_cause)
    VALUES (v_nas, v_sid, v_device, v_link, v_mac, v_called.bssid, v_called.ssid, np_inet(p_framed_ip),
            CASE WHEN v_status = 'start' THEN v_at ELSE v_at - make_interval(secs => coalesce(v_time, 0)) END,
            v_at, CASE WHEN v_status = 'stop' THEN v_at END, v_time, v_in, v_out,
            CASE WHEN v_status = 'stop' THEN v_cause END)
    ON CONFLICT (nas_ip, acct_session_id) DO UPDATE SET
        device_id = EXCLUDED.device_id,
        link = EXCLUDED.link,
        mac = coalesce(EXCLUDED.mac, a.mac),
        bssid = coalesce(EXCLUDED.bssid, a.bssid),
        ssid = coalesce(EXCLUDED.ssid, a.ssid),
        framed_ip = coalesce(EXCLUDED.framed_ip, a.framed_ip),
        started = CASE WHEN v_status = 'start' THEN EXCLUDED.started ELSE coalesce(a.started, EXCLUDED.started) END,
        updated = greatest(a.updated, EXCLUDED.updated),
        stopped = CASE WHEN v_status = 'stop' THEN EXCLUDED.stopped ELSE a.stopped END,
        session_time_s = greatest(a.session_time_s, EXCLUDED.session_time_s),
        input_octets = greatest(a.input_octets, EXCLUDED.input_octets),
        output_octets = greatest(a.output_octets, EXCLUDED.output_octets),
        terminate_cause = CASE WHEN v_status = 'stop' THEN coalesce(EXCLUDED.terminate_cause, a.terminate_cause)
                               ELSE a.terminate_cause END;

    IF v_device IS NOT NULL AND v_mac IS NOT NULL THEN
        INSERT INTO device_mac (device_id, mac, first_seen, last_seen, auth_count, randomized)
        VALUES (v_device, v_mac, v_at, v_at, 0, (v_mac & '02:00:00:00:00:00') = '02:00:00:00:00:00')
        ON CONFLICT (device_id, mac) DO UPDATE SET last_seen = greatest(device_mac.last_seen, EXCLUDED.last_seen);
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'radius_accounting: %', SQLERRM;
END $$;

-- --- backfill ------------------------------------------------------------------------------
-- The MAC identities known so far: the latest session per device (first login with that MAC,
-- latest login). A few rows at house size, so here rather than in a job.
INSERT INTO device_mac (device_id, mac, first_seen, last_seen, auth_count, randomized)
SELECT s.device_id, np_mac(s.calling_station), s.first_seen, greatest(s.first_seen, s.updated), 1,
       (np_mac(s.calling_station) & '02:00:00:00:00:00') = '02:00:00:00:00:00'
FROM radius_session s
WHERE np_mac(s.calling_station) IS NOT NULL
ON CONFLICT (device_id, mac) DO NOTHING;
