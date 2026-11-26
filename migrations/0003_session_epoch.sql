-- Portal sessions that can be ended on the server (docs/PARITY.md, web). The session cookie
-- is client-side (encrypted and signed) and carries the person's session epoch from the login;
-- a request whose cookie has an older epoch than the person's row is no longer logged in. The
-- epoch moves on at a logout (every portal session of the person ends, also a copy of the cookie
-- or a response still in flight that would set it again) and when the person is offboarded (so
-- a cookie from before the offboarding does not come back to life at the next login).

ALTER TABLE person ADD COLUMN session_epoch bigint NOT NULL DEFAULT 0 CHECK (session_epoch >= 0);
