-- Fixes of the security review of 2026-10-29 (rust/docs/PARITY.md, deliberate deviations).

-- The offboarding revokes a person's devices only when two rounds in a row found them without
-- access (an Authentik edit in progress, e.g. a move between the residents' and the guests'
-- groups, must not cost a re-enrolment). absent_since is when a round first found the person
-- without access; a round or a login that finds them allowed clears it.
ALTER TABLE person ADD COLUMN absent_since timestamptz;

-- The access decision as a security barrier: a condition the role radius adds to its query
-- (e.g. one that fails for a certain serial) is evaluated only on rows the view lets through,
-- so it cannot tell which revoked, retired or expired serials exist (radius.cert_status says
-- that on purpose, for the logged reason, and nothing more).
ALTER VIEW radius.valid_cert SET (security_barrier = true);
