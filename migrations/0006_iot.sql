-- Home (IoT) devices (house-infra docs/IOT-ACCESS.md, 2026-10-29): devices of a second kind that
-- join the IoT SSID with their own Wi-Fi key (UniFi PPSK) and their registered MAC (RADIUS MAC
-- authentication, view radius.iot_mac), owned by a person, shared with people or the house. The
-- controller sidecar (netportal iot) reconciles UniFi and OPNsense with these rows; the discovery
-- proxy (netportal discovery) reads iot_access with its read-only role (sql/discovery_grants.sql).

-- --- a second kind of device --------------------------------------------------------------------

ALTER TABLE device DROP CONSTRAINT device_kind_check;
ALTER TABLE device ADD CONSTRAINT device_kind_check CHECK (kind IN ('cert', 'iot'));
ALTER TABLE device DROP CONSTRAINT device_platform_check;
ALTER TABLE device ADD CONSTRAINT device_platform_check
    CHECK (platform IN ('apple', 'apple-mac', 'android', 'eap-config', 'letswifi', 'iot'));
-- an IoT device has no certificate and its platform is 'iot'; a certificate device never is
ALTER TABLE device ADD CONSTRAINT device_iot_platform CHECK ((kind = 'iot') = (platform = 'iot'));

-- The IoT part of a device: its class (the help texts and the proxy's service types; never the
-- firewall), the registered MAC (entered at registration or claimed from a join attempt; NULL
-- until then, so the key exists but RADIUS refuses every MAC), the device's own Wi-Fi key
-- (plain: UniFi needs it as it is, the owner may read it again; 20 characters of [A-Za-z0-9])
-- and who may see it in their pickers beyond the shares (visibility).
CREATE TABLE iot_device (
    device_id       uuid PRIMARY KEY REFERENCES device(id) ON DELETE CASCADE,
    class           text NOT NULL CHECK (class IN ('cast', 'airplay', 'printer', 'tv', 'speaker', 'other')),
    mac             macaddr UNIQUE,
    mac_claimed_at  timestamptz,
    psk             text NOT NULL CHECK (psk ~ '^[A-Za-z0-9]{12,63}$'),
    psk_rotated_at  timestamptz NOT NULL DEFAULT now(),
    visibility      text NOT NULL DEFAULT 'private' CHECK (visibility IN ('private', 'house')),
    CHECK ((mac IS NULL) = (mac_claimed_at IS NULL))
);

-- A share: the grantee may reach and see the device until the row is deleted (the audit keeps
-- the history: share:<sub>, unshare:<sub>).
CREATE TABLE iot_share (
    device_id   uuid NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    grantee     text NOT NULL REFERENCES person(sub),
    granted_by  text NOT NULL REFERENCES person(sub),
    granted_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, grantee)
);
CREATE INDEX iot_share_grantee ON iot_share (grantee);

-- Who may reach which IoT device: its owner, every grantee, and for a device visible to the
-- house every person with a policy who is not offboarded. Revoked devices and offboarded owners
-- give no access. Every consumer (the pages, the controller, the proxy) reads this view and
-- derives rights nowhere else.
CREATE VIEW iot_access AS
    SELECT d.owner AS sub, d.id AS device_id, 'owner'::text AS basis
    FROM device d JOIN iot_device i ON i.device_id = d.id JOIN person o ON o.sub = d.owner
    WHERE d.kind = 'iot' AND d.revoked_at IS NULL AND o.offboarded_at IS NULL
    UNION
    SELECT s.grantee, s.device_id, 'share'
    FROM iot_share s
    JOIN device d ON d.id = s.device_id JOIN person o ON o.sub = d.owner JOIN person g ON g.sub = s.grantee
    WHERE d.revoked_at IS NULL AND o.offboarded_at IS NULL AND g.offboarded_at IS NULL
    UNION
    SELECT p.sub, d.id, 'house'
    FROM device d JOIN iot_device i ON i.device_id = d.id JOIN person o ON o.sub = d.owner
    CROSS JOIN person p
    WHERE d.kind = 'iot' AND d.revoked_at IS NULL AND o.offboarded_at IS NULL
      AND i.visibility = 'house' AND p.policy IS NOT NULL AND p.offboarded_at IS NULL;

-- The controller's state per target and key: what the last round did with it. target: unifi_key
-- (key: device id), unifi_block (device id), opnsense_alias (alias name), opnsense_rule (person
-- sub or 'house'), opnsense_states (device id). The pages show it (a share is in effect when its
-- aliases are applied); pending and failed rows are counted by /metrics.
CREATE TABLE iot_sync (
    target      text NOT NULL CHECK (target IN ('unifi_key', 'unifi_block', 'opnsense_alias', 'opnsense_rule',
                                                'opnsense_states')),
    key         text NOT NULL CHECK (length(key) BETWEEN 1 AND 200),
    status      text NOT NULL CHECK (status IN ('applied', 'pending', 'failed')),
    detail      text NOT NULL DEFAULT '',
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (target, key)
);

-- MACs that tried to join the IoT SSID and were refused (unknown): the portal offers the ones of
-- the last minutes for a one-click claim. Written by radius.reject (reason unknown_mac), pruned
-- by the controller after a day.
CREATE TABLE iot_join_attempt (
    mac         macaddr PRIMARY KEY,
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    tries       integer NOT NULL DEFAULT 1 CHECK (tries >= 1),
    ssid        text,
    CHECK (last_seen >= first_seen)
);

-- --- the FreeRADIUS contract: MAC authentication --------------------------------------------------

-- The access decision of the IoT SSID: a registered MAC of an unrevoked IoT device whose owner
-- is not offboarded, with its device id (the login's). No VLAN here: the key's mapping in
-- UniFi gives it.
CREATE VIEW radius.iot_mac WITH (security_barrier = true) AS
    SELECT i.mac, d.id::text AS device_id
    FROM iot_device i JOIN device d ON d.id = i.device_id JOIN person o ON o.sub = d.owner
    WHERE i.mac IS NOT NULL AND d.kind = 'iot' AND d.revoked_at IS NULL AND o.offboarded_at IS NULL;

-- radius_auth gets the reason of a refused MAC.
ALTER TABLE radius_auth DROP CONSTRAINT radius_auth_reason_check;
ALTER TABLE radius_auth ADD CONSTRAINT radius_auth_reason_check
    CHECK (reason IN ('ok', 'unknown_cert', 'revoked', 'expired', 'retired', 'no_cert', 'bad_chain', 'not_eap',
                      'db_error', 'other', 'unknown_mac'));

-- radius.reject as in 0002, plus the hint unknown_mac (a MAC authentication the view refused):
-- logged as such, and the MAC noted in iot_join_attempt for the claim.
CREATE OR REPLACE FUNCTION radius.reject(p_serial text, p_calling text, p_called text, p_nas_ip text, p_reason_hint text)
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
        v_reason := CASE WHEN p_reason_hint IN ('no_cert', 'not_eap', 'bad_chain', 'db_error', 'unknown_mac')
                         THEN p_reason_hint ELSE 'other' END;
    END IF;
    IF v_reason = 'unknown_mac' AND v_mac IS NOT NULL THEN
        BEGIN
            INSERT INTO iot_join_attempt (mac, ssid) VALUES (v_mac, left(v_called.ssid, 32))
            ON CONFLICT (mac) DO UPDATE
                SET last_seen = greatest(iot_join_attempt.last_seen, now()), tries = iot_join_attempt.tries + 1,
                    ssid = coalesce(excluded.ssid, iot_join_attempt.ssid);
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'radius.reject: iot_join_attempt: %', SQLERRM;
        END;
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
