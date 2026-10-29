-- The rights of FreeRADIUS's role "radius", declaratively: run after every migration run (not a
-- versioned migration, so it may change freely; registry::migrate). Everything is revoked, then
-- exactly the contract is granted: USAGE on the schema radius, SELECT on its views, EXECUTE on
-- its functions (docs/RADIUS_CONTRACT.md). The role is created outside the application
-- (house-infra); when it is missing this only warns (migrate reports it, /metrics shows it).

-- Functions are executable by PUBLIC by default: none of ours is.
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA radius FROM PUBLIC;
REVOKE ALL ON SCHEMA radius FROM PUBLIC;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'radius') THEN
        RAISE WARNING 'netportal: the role radius does not exist: FreeRADIUS cannot read the registry';
        RETURN;
    END IF;
    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM radius;
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM radius;
    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM radius;
    REVOKE ALL ON ALL TABLES IN SCHEMA radius FROM radius;
    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA radius FROM radius;
    GRANT USAGE ON SCHEMA radius TO radius;
    GRANT SELECT ON ALL TABLES IN SCHEMA radius TO radius;
    GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA radius TO radius;
    -- A slow registry must not hold up a RADIUS answer (the access points retry after a few
    -- seconds): a decision query that runs into this fails closed, a logging call silently.
    -- Needs the right to alter the role; without it the role keeps the server's defaults. Set
    -- only when they differ: an owner that is no superuser (house-infra's netportal_rust, whose
    -- init sets these values as the superuser) then starts without a warning.
    IF NOT EXISTS (
        SELECT 1 FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole
        WHERE r.rolname = 'radius' AND s.setdatabase = 0
          AND s.setconfig @> ARRAY['statement_timeout=2s', 'lock_timeout=1s']
    ) THEN
        BEGIN
            ALTER ROLE radius SET statement_timeout = '2s';
            ALTER ROLE radius SET lock_timeout = '1s';
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE WARNING 'netportal: cannot set the radius role''s timeouts: %', SQLERRM;
        END;
    END IF;
END $$;
