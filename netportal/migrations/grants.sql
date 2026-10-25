-- The rights of FreeRADIUS's role "radius", declaratively: run after every migrate (not a
-- versioned migration, so it may change freely). Everything is revoked, then exactly this list
-- is granted:
--   SELECT on the decision view radius_cert,
--   EXECUTE on the functions FreeRADIUS logs through (they write as the schema owner) and the
--   two helpers it may call: radius_login, radius_reject, radius_accounting, radius_cert_status,
--   np_mac.
-- No table: since 2026-10-25 the functions write radius_session, radius_auth, radius_acct and
-- device_mac. The role is created by the stack (house-infra stacks/netaccess); when it is missing
-- this only warns (registry.migrate logs it, /metrics shows it): FreeRADIUS then rejects every
-- login, as it cannot read the registry.

-- Functions are executable by PUBLIC by default: none of ours is.
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'radius') THEN
        RAISE WARNING 'netportal: the role radius does not exist: FreeRADIUS cannot read the registry';
        RETURN;
    END IF;
    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM radius;
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM radius;
    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM radius;
    GRANT SELECT ON radius_cert TO radius;
    GRANT EXECUTE ON FUNCTION
        radius_login(text, text, text, text, text, text, text),
        radius_reject(text, text, text, text, text),
        radius_accounting(text, text, text, text, text, text, text, text, text, text, text, text, text, text),
        radius_cert_status(text),
        np_mac(text)
    TO radius;
    -- A slow registry must not hold up a RADIUS answer: the access points retry after a few
    -- seconds. A decision query that runs into this fails closed (reject); a logging call
    -- fails silently (it runs on FreeRADIUS's separate logging pool, radius/mods/sql_log, and
    -- the logging functions wait for row locks only 500 ms themselves: 0002_telemetry.sql).
    -- Needs the right to alter the role (the stack's netportal user is the database superuser);
    -- without it the role keeps the server's defaults.
    BEGIN
        ALTER ROLE radius SET statement_timeout = '2s';
        ALTER ROLE radius SET lock_timeout = '1s';
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE WARNING 'netportal: cannot set the radius role''s timeouts: %', SQLERRM;
    END;
END $$;
