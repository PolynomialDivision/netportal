-- The device registry (PostgreSQL). netportal owns it; FreeRADIUS (role radius) may only read
-- the radius_* views and write radius_session. Wi-Fi uses kind 'cert'; 'mac' and 'ppsk' are
-- reserved for wired MAC authentication and IoT keys (not implemented yet).
-- Idempotent: run at every portal start.

CREATE TABLE IF NOT EXISTS person (
    sub         text PRIMARY KEY,            -- OIDC subject (Authentik hashed user id)
    username    text NOT NULL,
    display     text NOT NULL,
    last_login  timestamptz NOT NULL DEFAULT now()
);
-- Set by the offboarding when the person left the Wi-Fi groups: the portal session ends and the
-- apps' tokens stop working at once; cleared by the next successful login.
ALTER TABLE person ADD COLUMN IF NOT EXISTS offboarded timestamptz;

CREATE TABLE IF NOT EXISTS policy (
    name  text PRIMARY KEY,                  -- residents (default), later iot, vpn-<exit> ...
    vlan  integer NOT NULL CHECK (vlan BETWEEN 1 AND 4094)
);

CREATE TABLE IF NOT EXISTS device (
    id          uuid PRIMARY KEY,            -- also the certificate subject <id>@<realm>
    owner       text NOT NULL,               -- person.sub, later household:<name> / infra
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 60),
    kind        text NOT NULL CHECK (kind IN ('cert', 'mac', 'ppsk')),
    platform    text NOT NULL,               -- apple, android, letswifi, eap-config
    policy      text NOT NULL REFERENCES policy(name),
    created     timestamptz NOT NULL DEFAULT now(),
    revoked     timestamptz
);
CREATE INDEX IF NOT EXISTS device_owner ON device (owner);

CREATE TABLE IF NOT EXISTS credential (
    serial      text PRIMARY KEY,            -- certificate serial, lowercase hex as FreeRADIUS reports it
    device_id   uuid NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    issued      timestamptz NOT NULL DEFAULT now(),
    not_after   timestamptz NOT NULL,
    -- a renewal keeps the previous certificate valid for a short overlap, then this ends it
    retired_after timestamptz
);
CREATE INDEX IF NOT EXISTS credential_device ON credential (device_id);

-- The latest RADIUS session per device (no history): where to send a Disconnect-Request.
CREATE TABLE IF NOT EXISTS radius_session (
    device_id        uuid PRIMARY KEY REFERENCES device(id) ON DELETE CASCADE,
    nas_ip           text NOT NULL,
    calling_station  text NOT NULL,
    user_name        text NOT NULL,
    updated          timestamptz NOT NULL DEFAULT now()
);

-- One-time downloads: a device's profile is generated (key and certificate made) only when the
-- link is opened, once, within minutes. No key is ever stored.
CREATE TABLE IF NOT EXISTS download (
    token       text PRIMARY KEY,
    device_id   uuid NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    format      text NOT NULL CHECK (format IN ('apple', 'apple-mac', 'android', 'eap-config')),
    expires     timestamptz NOT NULL
);

-- OAuth for the geteduroam apps (Let's Wi-Fi API): codes, access and refresh tokens are stored
-- as SHA-256 hashes only.
CREATE TABLE IF NOT EXISTS oauth_grant (
    id            uuid PRIMARY KEY,
    owner         text NOT NULL,
    client_id     text NOT NULL,
    device_name   text NOT NULL,
    device_id     uuid REFERENCES device(id) ON DELETE CASCADE,   -- set at the first eap-config
    created       timestamptz NOT NULL DEFAULT now(),
    revoked       timestamptz
);
CREATE TABLE IF NOT EXISTS oauth_token (
    hash        text PRIMARY KEY,
    grant_id    uuid NOT NULL REFERENCES oauth_grant(id) ON DELETE CASCADE,
    kind        text NOT NULL CHECK (kind IN ('code', 'access', 'refresh')),
    expires     timestamptz NOT NULL,
    used        timestamptz,
    pkce_challenge text,                       -- codes only
    redirect_uri   text                        -- codes only
);

-- Background jobs (the offboarding sidecar is its own process): when they last succeeded, so
-- the portal's /metrics can show it.
CREATE TABLE IF NOT EXISTS job (
    name          text PRIMARY KEY,
    last_success  timestamptz NOT NULL
);

-- Admin actions and revocations (who, what, when); kept 90 days.
CREATE TABLE IF NOT EXISTS audit (
    at      timestamptz NOT NULL DEFAULT now(),
    actor   text NOT NULL,
    action  text NOT NULL,
    device_id uuid
);

CREATE OR REPLACE VIEW radius_cert AS
    SELECT c.serial, d.id::text AS device_id, p.vlan
    FROM credential c
    JOIN device d ON d.id = c.device_id
    JOIN policy p ON p.name = d.policy
    WHERE d.kind = 'cert' AND d.revoked IS NULL
      AND c.not_after > now()
      AND (c.retired_after IS NULL OR c.retired_after > now());

-- The default policy 'residents' and its VLAN are set by registry.init (NETPORTAL_DEFAULT_VLAN).

-- FreeRADIUS's role (created by the stack): read the decision view, write the latest session.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'radius') THEN
        GRANT SELECT ON radius_cert TO radius;
        GRANT SELECT, INSERT, UPDATE ON radius_session TO radius;
    END IF;
END $$;
