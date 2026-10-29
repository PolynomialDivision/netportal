-- The registry of the Rust netportal (its own database; designed from the Python schema,
-- netportal/migrations/0001-0003, with the fixes listed in docs/PARITY.md, "Deliberate
-- deviations", database). Applied by sqlx's migrator (table _sqlx_migrations); never edit an
-- applied migration, add a new one. The FreeRADIUS contract (schema radius) is 0002; the radius
-- role's rights are sql/radius_grants.sql, applied after every migration run.
--
-- Conventions: timestamps are timestamptz (`*_at` for moments the portal sets, the telemetry
-- names first_seen / last_seen / started / updated / stopped for observed ones); MACs are
-- macaddr, addresses inet; every foreign key has an index; enumerations are CHECKed.

-- --- people, policies, devices -------------------------------------------------------------------

-- Where a person's devices go: a name and the VLAN RADIUS assigns (NETPORTAL_POLICIES, seeded at
-- every start; never deleted, devices refer to them).
CREATE TABLE policy (
    name  text PRIMARY KEY CHECK (name ~ '^[a-z0-9][a-z0-9-]*$'),
    vlan  integer NOT NULL CHECK (vlan BETWEEN 1 AND 4094)
);

CREATE TABLE person (
    sub            text PRIMARY KEY CHECK (sub <> ''),      -- OIDC subject (Authentik hashed user id)
    username       text NOT NULL,
    display_name   text NOT NULL,
    -- the policy the person's groups give (login and every offboarding round); NULL: none yet
    policy         text REFERENCES policy(name),
    -- in the admin groups: set at login and every offboarding round, checked on every request
    is_admin       boolean NOT NULL DEFAULT false,
    last_login_at  timestamptz NOT NULL DEFAULT now(),
    -- set when the person left the Wi-Fi groups (sessions and app tokens stop at once); cleared
    -- by the next login
    offboarded_at  timestamptz
);
CREATE INDEX person_policy ON person (policy);

CREATE TABLE device (
    id          uuid PRIMARY KEY,                -- also the certificate subject <id>@<realm>
    owner       text NOT NULL REFERENCES person(sub),
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 60 AND btrim(name) <> ''),
    -- how it authenticates; only certificates today (MAC / PPSK devices would extend this)
    kind        text NOT NULL DEFAULT 'cert' CHECK (kind IN ('cert')),
    platform    text NOT NULL CHECK (platform IN ('apple', 'apple-mac', 'android', 'eap-config', 'letswifi')),
    policy      text NOT NULL REFERENCES policy(name),
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz,
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE INDEX device_owner ON device (owner);
CREATE INDEX device_policy ON device (policy);

-- Certificates of a device. The serial is the lowercase hex of the certificate's serial number,
-- an even number of digits (what FreeRADIUS compares, lower-cased, with TLS-Client-Cert-Serial).
CREATE TABLE credential (
    serial      text PRIMARY KEY CHECK (serial ~ '^([0-9a-f]{2})+$'),
    device_id   uuid NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    issued_at   timestamptz NOT NULL DEFAULT now(),
    not_after   timestamptz NOT NULL,
    -- a renewal keeps the previous certificate valid for a short overlap; it ends then
    retired_at  timestamptz,
    CHECK (not_after > issued_at)
);
CREATE INDEX credential_device ON credential (device_id);

-- The latest RADIUS login per device (no history; that is device_mac / radius_auth): where a
-- Disconnect-Request goes. Written by radius.login.
CREATE TABLE radius_session (
    device_id        uuid PRIMARY KEY REFERENCES device(id) ON DELETE CASCADE,
    nas_ip           inet NOT NULL,
    calling_station  text NOT NULL,              -- the MAC as the access point sent it
    user_name        text NOT NULL,              -- the outer identity
    first_seen       timestamptz NOT NULL DEFAULT now(),   -- first login with this calling_station
    updated          timestamptz NOT NULL DEFAULT now()
);

-- One-time downloads: the profile (key and certificate) is made only when the link is opened,
-- once, within minutes. Only the SHA-256 of the token is stored; no key is ever stored.
CREATE TABLE download (
    token_hash  text PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    device_id   uuid NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    format      text NOT NULL CHECK (format IN ('apple', 'apple-mac', 'android', 'eap-config')),
    expires_at  timestamptz NOT NULL
);
CREATE INDEX download_device ON download (device_id);
CREATE INDEX download_expires ON download (expires_at);

-- OAuth for the geteduroam apps (Let's Wi-Fi): a grant per app login, its tokens stored as
-- SHA-256 only.
CREATE TABLE oauth_grant (
    id           uuid PRIMARY KEY,
    owner        text NOT NULL REFERENCES person(sub),
    client_id    text NOT NULL CHECK (client_id <> ''),
    device_name  text NOT NULL CHECK (length(device_name) BETWEEN 1 AND 60 AND btrim(device_name) <> ''),
    device_id    uuid REFERENCES device(id) ON DELETE CASCADE,   -- set at the first eap-config
    created_at   timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz
);
CREATE INDEX oauth_grant_owner ON oauth_grant (owner);
CREATE INDEX oauth_grant_device ON oauth_grant (device_id);

CREATE TABLE oauth_token (
    token_hash      text PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    grant_id        uuid NOT NULL REFERENCES oauth_grant(id) ON DELETE CASCADE,
    kind            text NOT NULL CHECK (kind IN ('code', 'access', 'refresh')),
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz,
    pkce_challenge  text,                        -- codes only
    redirect_uri    text,                        -- codes only
    CHECK (kind = 'code' OR (pkce_challenge IS NULL AND redirect_uri IS NULL))
);
CREATE INDEX oauth_token_grant ON oauth_token (grant_id);
CREATE INDEX oauth_token_expires ON oauth_token (expires_at);

-- Background jobs (offboarding, the collector's jobs): when they last ran and succeeded.
CREATE TABLE job (
    name          text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9_]*$'),
    last_success  timestamptz,
    last_attempt  timestamptz,
    last_error    text CHECK (length(last_error) <= 2000),
    duration_s    double precision CHECK (duration_s >= 0),
    cursor        jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(cursor) = 'object')
);

-- Who did what to which device (no foreign key: the log outlives what it names); kept 90 days.
CREATE TABLE audit (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at         timestamptz NOT NULL DEFAULT now(),
    actor      text NOT NULL,                    -- person.sub, 'offboarding' or 'system'
    action     text NOT NULL,                    -- enrol:<format>, renew, revoke, disconnect:<result>, ...
    device_id  uuid
);
CREATE INDEX audit_at ON audit (at);
CREATE INDEX audit_device ON audit (device_id);

-- --- telemetry: identities, RADIUS decisions and sessions, UniFi events --------------------------

-- MAC identities: when a device's certificate logged in with which MAC. A window is
-- [first_seen, window_end] (view device_mac_window): data of the MAC in it belongs to the device.
CREATE TABLE device_mac (
    device_id   uuid NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    mac         macaddr NOT NULL,
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,             -- last login, accounting or UniFi event with it
    auth_count  integer NOT NULL DEFAULT 0 CHECK (auth_count >= 0),
    randomized  boolean NOT NULL,                 -- the locally administered bit
    PRIMARY KEY (device_id, mac),
    CHECK (last_seen >= first_seen)
);
CREATE INDEX device_mac_mac ON device_mac (mac, first_seen);

-- Every RADIUS decision with its reason. Repeated rejects are one row (radius.reject): `tries`
-- decisions from `at` (the first) to `last_at` (the latest; NULL while there is only one).
CREATE TABLE radius_auth (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at               timestamptz NOT NULL DEFAULT now(),
    tries            integer NOT NULL DEFAULT 1 CHECK (tries >= 1),
    last_at          timestamptz,
    result           text NOT NULL CHECK (result IN ('accept', 'reject')),
    reason           text NOT NULL CHECK (reason IN ('ok', 'unknown_cert', 'revoked', 'expired', 'retired',
                                                     'no_cert', 'bad_chain', 'not_eap', 'db_error', 'other')),
    device_id        uuid REFERENCES device(id) ON DELETE SET NULL,
    serial           text,
    mac              macaddr,
    nas_ip           inet,
    bssid            macaddr,                     -- from Called-Station-Id "<BSSID>:<SSID>"
    ssid             text,
    class_token      text UNIQUE,                 -- the Class of the Accept (accepts only)
    acct_session_id  text,
    CHECK ((result = 'accept') = (reason = 'ok')),
    CHECK (result = 'accept' OR class_token IS NULL),
    CHECK (last_at IS NULL OR last_at >= at)
);
CREATE INDEX radius_auth_device ON radius_auth (device_id, at);
CREATE INDEX radius_auth_at ON radius_auth (at);
CREATE INDEX radius_auth_mac ON radius_auth (mac, at);

-- RADIUS accounting sessions (one row per NAS session).
CREATE TABLE radius_acct (
    nas_ip           inet NOT NULL,
    acct_session_id  text NOT NULL CHECK (length(acct_session_id) BETWEEN 1 AND 253),
    device_id        uuid REFERENCES device(id) ON DELETE SET NULL,   -- by Class, else MAC window
    link             text NOT NULL CHECK (link IN ('class', 'mac_window', 'none')),
    mac              macaddr,
    bssid            macaddr,
    ssid             text,
    framed_ip        inet,
    started          timestamptz,
    updated          timestamptz NOT NULL,
    stopped          timestamptz,
    session_time_s   bigint CHECK (session_time_s >= 0),
    input_octets     bigint CHECK (input_octets >= 0),    -- the AP's view: device upload
    output_octets    bigint CHECK (output_octets >= 0),   -- device download
    terminate_cause  text,
    interim_s        integer CHECK (interim_s BETWEEN 30 AND 86400),  -- measured interval
    PRIMARY KEY (nas_ip, acct_session_id)
);
CREATE INDEX radius_acct_device ON radius_acct (device_id, updated);
CREATE INDEX radius_acct_updated ON radius_acct (updated);
CREATE INDEX radius_acct_open ON radius_acct (nas_ip) WHERE stopped IS NULL;

-- Per access point (NAS address): the measured accounting interval and its latest
-- Accounting-On/Off.
CREATE TABLE radius_nas (
    nas_ip       inet PRIMARY KEY,
    interim_s    integer CHECK (interim_s BETWEEN 30 AND 86400),
    interim_at   timestamptz,
    reset_at     timestamptz,
    reset_cause  text CHECK (reset_cause IN ('NAS-Reboot', 'NAS-Request'))
);

-- Connection events from UniFi's system log (Loki -> collector).
CREATE TABLE connection_event (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at            timestamptz NOT NULL,
    mac           macaddr NOT NULL,
    device_id     uuid REFERENCES device(id) ON DELETE SET NULL,   -- by MAC window at ingest
    kind          text NOT NULL CHECK (kind IN ('connected', 'disconnected', 'roamed', 'other')),
    source        text NOT NULL CHECK (source IN ('unifi_syslog')),
    ap_mac        macaddr,
    ap_name       text,
    from_ap_mac   macaddr,
    from_ap_name  text,
    ssid          text,
    radio         text,
    channel       integer,
    rssi          integer,
    duration_s    bigint,
    rx_bytes      bigint,
    tx_bytes      bigint,
    detail        jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(detail) = 'object'),
    dedup_key     text NOT NULL UNIQUE CHECK (length(dedup_key) BETWEEN 1 AND 512)
);
CREATE INDEX connection_event_device ON connection_event (device_id, at);
CREATE INDEX connection_event_mac ON connection_event (mac, at);
CREATE INDEX connection_event_at ON connection_event (at);

-- --- rollups and incidents -----------------------------------------------------------------------

-- Per device and house day (NETPORTAL_TIMEZONE), from Prometheus; idempotent per (device, day).
CREATE TABLE device_day (
    device_id        uuid NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    day              date NOT NULL,
    online_s         integer CHECK (online_s >= 0),
    stale_s          integer CHECK (stale_s >= 0),
    signal_avg_dbm   double precision,
    signal_p10_dbm   double precision,
    snr_avg_db       double precision,
    health_avg       double precision,
    health_min       double precision,
    retry_ratio_avg  double precision,
    rx_bytes         bigint,
    tx_bytes         bigint,
    link_rx_avg_bps  double precision,
    roams            integer,
    reconnects       integer,
    disconnects      integer,
    aps              jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(aps) = 'object'),    -- {ap_mac: seconds}
    bands            jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(bands) = 'object'),  -- {"2.4"|"5"|"6": seconds}
    macs             integer,
    auth_ok          integer,
    auth_failed      integer,
    computed_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, day)
);

-- Per access point (by MAC) and house day.
CREATE TABLE ap_day (
    ap_mac             macaddr NOT NULL,
    day                date NOT NULL,
    ap_name            text,
    clients_avg        double precision,
    clients_max        integer,
    channel_util_avg   jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(channel_util_avg) = 'object'),  -- {radio: ratio}
    weak_client_share  double precision,
    restarts           integer,
    down_s             integer,
    computed_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ap_mac, day)
);

-- Infrastructure incidents derived from monitoring; open while ended is NULL.
CREATE TABLE incident (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind          text NOT NULL CHECK (kind IN ('internet_down', 'internet_degraded', 'router_down', 'dns_down',
                                               'ap_down', 'ap_restarted', 'switch_down', 'switch_port_down',
                                               'unifi_data_stale', 'radius_down')),
    subject       text NOT NULL DEFAULT '',      -- AP MAC, switch, port; '' for house-wide
    subject_name  text,
    started       timestamptz NOT NULL,
    ended         timestamptz,
    basis         text NOT NULL CHECK (basis IN ('measured', 'inferred')),
    detail        jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(detail) = 'object'),
    UNIQUE (kind, subject, started),
    CHECK (ended IS NULL OR ended >= started)
);
CREATE INDEX incident_time ON incident (started, ended);
-- At most one open incident per kind and subject (open_incident relies on it).
CREATE UNIQUE INDEX incident_open ON incident (kind, subject) WHERE ended IS NULL;

-- --- helpers (input normalisation; never raise) --------------------------------------------------

-- The MAC normaliser (netportal_core::registry::normalise_mac is its Rust twin, tested against
-- it): AA-BB-CC-DD-EE-FF, aa:bb:cc:dd:ee:ff or 12 bare hex digits, any case, surrounding ASCII
-- whitespace ignored; anything else -> NULL.
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
-- BSSID gives no SSID; anything else (NULL, NULL).
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

-- --- MAC windows ---------------------------------------------------------------------------------
-- [first_seen, window_end]: window_end = last_seen + 15 min (WINDOW_GRACE), except for the
-- device's CURRENT window (its MAC with the newest last_seen, device not revoked): last_seen +
-- 12 h 15 min (CURRENT_WINDOW), but not beyond now. A device logs in again at least every 12 h
-- (RADIUS Session-Timeout 43200 in the stack: change both together).
CREATE VIEW device_mac_window AS
    SELECT w.device_id, w.mac, w.first_seen, w.last_seen, w.auth_count, w.randomized, w.current,
           CASE WHEN w.current
                THEN least(w.last_seen + interval '12 hours 15 minutes',
                           greatest(now(), w.last_seen + interval '15 minutes'))
                ELSE w.last_seen + interval '15 minutes' END AS window_end
    FROM (SELECT m.*, (d.revoked_at IS NULL AND m.last_seen = max(m.last_seen) OVER (PARTITION BY m.device_id))
                 AS current
          FROM device_mac m JOIN device d ON d.id = m.device_id) w;

-- The device a MAC belonged to at a time: the windows containing it; NULL when none, or when
-- devices of more than one owner claim it then (a conflict: the data belongs to nobody). Several
-- devices of one owner (a re-enrolment): the one seen last.
CREATE FUNCTION np_device_for_mac(p_mac macaddr, p_at timestamptz) RETURNS uuid
LANGUAGE sql STABLE SET search_path = public, pg_temp AS $$
    SELECT CASE WHEN count(DISTINCT d.owner) = 1
                THEN (array_agg(w.device_id ORDER BY w.last_seen DESC))[1] END
    FROM device_mac_window w JOIN device d ON d.id = w.device_id
    WHERE w.mac = p_mac AND p_at >= w.first_seen AND p_at <= w.window_end
$$;
