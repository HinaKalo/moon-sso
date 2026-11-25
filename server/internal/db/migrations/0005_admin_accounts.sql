-- The admin console has its own identities and sessions: administrators are
-- not SSO users, cannot sign in to the SSO or any application, and SSO users
-- cannot sign in to the console.

CREATE TABLE IF NOT EXISTS admin_accounts (
  id                    BINARY(16)      NOT NULL,
  username              VARCHAR(32)     NOT NULL,
  username_norm         VARCHAR(32)     NOT NULL,
  display_name          VARCHAR(64)     NOT NULL DEFAULT '',
  password_hash         VARCHAR(160)    NOT NULL,
  password_changed_at   DATETIME(3)     NOT NULL,
  must_change_password  TINYINT(1)      NOT NULL DEFAULT 1,
  totp_secret_enc       VARBINARY(160)  NULL,
  totp_last_step        BIGINT          NOT NULL DEFAULT 0,
  status                TINYINT         NOT NULL DEFAULT 1,
  created_at            DATETIME(3)     NOT NULL,
  updated_at            DATETIME(3)     NOT NULL,
  last_login_at         DATETIME(3)     NULL,
  last_login_ip         VARCHAR(45)     NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  UNIQUE KEY uq_admin_username (username_norm)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS admin_sessions (
  id               BINARY(32)    NOT NULL,
  admin_id         BINARY(16)    NOT NULL,
  created_at       DATETIME(3)   NOT NULL,
  last_seen_at     DATETIME(3)   NOT NULL,
  idle_expires_at  DATETIME(3)   NOT NULL,
  abs_expires_at   DATETIME(3)   NOT NULL,
  ip               VARCHAR(45)   NOT NULL DEFAULT '',
  user_agent       VARCHAR(255)  NOT NULL DEFAULT '',
  revoked_at       DATETIME(3)   NULL,
  PRIMARY KEY (id),
  KEY idx_admin_sessions_admin (admin_id, revoked_at),
  KEY idx_admin_sessions_expiry (abs_expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

ALTER TABLE audit_log ADD COLUMN actor_admin VARCHAR(32) NOT NULL DEFAULT '' AFTER actor_client_id;

-- Remove the former OIDC coupling (built-in "sso-admin" client, admin role on users).
UPDATE refresh_families SET revoked_at = UTC_TIMESTAMP(3), revoke_reason = 'admin_decoupled' WHERE client_id = 'sso-admin' AND revoked_at IS NULL;
DELETE FROM session_clients WHERE client_id = 'sso-admin';
DELETE FROM client_events WHERE client_id = 'sso-admin';
DELETE FROM grants WHERE client_id = 'sso-admin';
DELETE FROM clients WHERE id = 'sso-admin';
UPDATE users SET roles = roles & ~1 WHERE (roles & 1) = 1;
