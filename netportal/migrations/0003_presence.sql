-- Migration 0003: device presence (docs/TELEMETRY.md, "Presence"). Additive: the previous
-- release keeps working on this schema (it reads none of the new columns; the function keeps
-- its signature and grants).
--
-- radius_acct.interim_s: the measured accounting interval of a session, the smallest gap between
-- two consecutive updates (Start or Interim, then Interim) by their Event-Timestamp. The presence
-- rules call a session abandoned (its access point lost power, a Stop got lost) once it has been
-- silent for 2 x interval + 60 s; the interval measured, clamped to [configured, 4 x configured],
-- beats the configured one (NETPORTAL_ACCT_INTERIM_S, which FreeRADIUS also sends as
-- Acct-Interim-Interval).
-- radius_nas: per access point (NAS address) the measured interval of its sessions (for one that
-- has only its Start so far) and its latest Accounting-On/Off (a reordered Start or Interim from
-- before it still ends there).

ALTER TABLE radius_acct ADD COLUMN interim_s integer;

CREATE TABLE radius_nas (
    nas_ip      inet PRIMARY KEY,
    interim_s   integer,                  -- the latest measured interval of one of its sessions
    interim_at  timestamptz,              -- the update that measured it
    reset_at    timestamptz,              -- the latest Accounting-On/Off (its Event-Timestamp)
    reset_cause text                      -- NAS-Reboot (On) | NAS-Request (Off)
);

-- radius_accounting, the same signature (grants.sql grants it to radius), now:
-- - order-proof: every time is the packet's Event-Timestamp when plausible (within 7 days back,
--   never later than now: an access point's clock ahead is taken as now), else its arrival;
--   updated only moves forward; started is the earliest a Start or an estimate (time minus
--   Acct-Session-Time) gave; a Stop ends only its own (nas_ip, acct_session_id), also when it
--   arrived before its Start or an Interim; a retransmitted Stop keeps the first stop time.
-- - a reused Acct-Session-Id: a Start newer than the session's Stop, or an Interim more than an
--   interval after it, opens the session again (started anew, stopped and cause cleared,
--   counters from the packet).
-- - Accounting-On/Off close the NAS's sessions that began before it (an older, reordered On/Off
--   never ends a newer session) at the On/Off, or, for a session silent for longer than
--   2 x its interval + 60 s, at that point (it was abandoned before; its updated, the last
--   contact, stays). They are remembered (radius_nas.reset_at): a Start or Interim from before
--   the latest On/Off that arrives after it ends its session there, unless the session has been
--   updated after it.
-- - measuring: an Interim newer than the session's latest update by 30 s .. 1 day is a gap; the
--   session's interim_s is the smallest gap seen (a lost packet, an outage only make longer
--   ones; duplicates and reordered packets have no positive gap); the NAS's interim_s follows
--   the session estimates when they differ from it by more than 10 %. The presence rules clamp
--   the interval to [configured, 4 x configured]. A failed radius_nas write (a lock timeout)
--   loses only that write, never the session's.
CREATE OR REPLACE FUNCTION radius_accounting(p_status text, p_acct_session_id text, p_class text, p_calling text,
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
            RAISE WARNING 'radius_accounting: radius_nas: %', SQLERRM;
        END;
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
    SELECT link, device_id, updated, stopped, interim_s INTO v_old
      FROM radius_acct WHERE nas_ip = v_nas AND acct_session_id = v_sid;
    v_found := FOUND;
    IF v_link = 'none' AND v_found AND v_old.link <> 'none' THEN
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
    -- The same Acct-Session-Id again after its Stop: a new session.
    IF v_found AND v_old.stopped IS NOT NULL AND (
           (v_status = 'start' AND v_at > v_old.stopped)
           OR (v_status = 'interim-update'
               AND v_at > v_old.stopped + make_interval(secs => greatest(coalesce(v_old.interim_s, 300), 60)))) THEN
        v_reopen := true;
    END IF;
    -- A gap: an Interim after the open session's latest update (a duplicate has no gap, a
    -- reordered older one a negative gap, a retransmission without Event-Timestamp a few
    -- seconds: none of them counts).
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
            RAISE WARNING 'radius_accounting: radius_nas: %', SQLERRM;
        END;
    END IF;

    IF v_device IS NOT NULL AND v_mac IS NOT NULL THEN
        INSERT INTO device_mac (device_id, mac, first_seen, last_seen, auth_count, randomized)
        VALUES (v_device, v_mac, v_at, v_at, 0, (v_mac & '02:00:00:00:00:00') = '02:00:00:00:00:00')
        ON CONFLICT (device_id, mac) DO UPDATE SET last_seen = greatest(device_mac.last_seen, EXCLUDED.last_seen);
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'radius_accounting: %', SQLERRM;
END $$;
