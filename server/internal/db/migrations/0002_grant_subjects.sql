-- The subject identifier issued to each client (public or pairwise) is stored
-- on the grant so APIs can map an incoming "sub" back to the user.
ALTER TABLE grants ADD COLUMN sub CHAR(22) NOT NULL DEFAULT '' AFTER client_id;
CREATE INDEX idx_grants_client_sub ON grants (client_id, sub);
