-- The rights of the discovery proxy's role "netportal_rust_discovery" (netportal discovery), run
-- after every migration run like sql/radius_grants.sql: everything revoked, then SELECT on exactly
-- what the proxy reads (who may reach which device, the devices' MACs and classes, the residents'
-- MAC windows). No write right, no function, nothing of the sessions, tokens or audit. The role
-- is created outside the application (house-infra stacks/netaccess files/init-rust-db.sh); when it
-- is missing this only warns.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netportal_rust_discovery') THEN
        RAISE WARNING 'netportal: the role netportal_rust_discovery does not exist: the discovery proxy cannot read the registry';
        RETURN;
    END IF;
    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM netportal_rust_discovery;
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM netportal_rust_discovery;
    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM netportal_rust_discovery;
    REVOKE ALL ON SCHEMA radius FROM netportal_rust_discovery;
    GRANT USAGE ON SCHEMA public TO netportal_rust_discovery;
    GRANT SELECT ON iot_access, iot_share, device, device_mac, device_mac_window, person, policy
        TO netportal_rust_discovery;
    -- the proxy answers for a device's MAC, class and visibility; its Wi-Fi key is none of its business
    GRANT SELECT (device_id, class, mac, mac_claimed_at, visibility) ON iot_device TO netportal_rust_discovery;
END $$;
