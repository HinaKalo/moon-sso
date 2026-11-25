-- Long-lived API tokens for terminals, scripts and CI.
--   kind 1: developer token, owned by an SSO user, accepted only on the public host.
--   kind 2: console token, owned by a console administrator, accepted only on the admin host.
-- Only an HMAC of the token is stored; the plaintext is shown once at issue.

CREATE TABLE IF NOT EXISTS api_tokens (
  id             BINARY(16)     NOT NULL,
  kind           TINYINT        NOT NULL,
  owner_id       BINARY(16)     NOT NULL,
  name           VARCHAR(64)    NOT NULL,
  scopes         VARCHAR(512)   NOT NULL,
  token_hash     VARBINARY(32)  NOT NULL,
  hint           VARCHAR(32)    NOT NULL,
  allowed_cidrs  VARCHAR(512)   NOT NULL DEFAULT '',
  created_at     DATETIME(3)    NOT NULL,
  created_ip     VARCHAR(45)    NOT NULL DEFAULT '',
  expires_at     DATETIME(3)    NOT NULL,
  last_used_at   DATETIME(3)    NULL,
  last_used_ip   VARCHAR(45)    NOT NULL DEFAULT '',
  revoked_at     DATETIME(3)    NULL,
  revoke_reason  VARCHAR(32)    NOT NULL DEFAULT '',
  rotated_from   BINARY(16)     NULL,
  replaced_by    BINARY(16)     NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_api_tokens_hash (token_hash),
  KEY idx_api_tokens_owner (kind, owner_id, revoked_at),
  KEY idx_api_tokens_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
