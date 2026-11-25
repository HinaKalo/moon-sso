-- Moon SSO initial schema. All timestamps are UTC DATETIME(3).

CREATE TABLE IF NOT EXISTS users (
  id                    BINARY(16)      NOT NULL,
  public_sub            CHAR(22)        NOT NULL,
  username              VARCHAR(32)     NOT NULL,
  username_norm         VARCHAR(32)     NOT NULL,
  display_name          VARCHAR(64)     NOT NULL DEFAULT '',
  password_hash         VARCHAR(160)    NOT NULL,
  password_changed_at   DATETIME(3)     NOT NULL,
  must_change_password  TINYINT(1)      NOT NULL DEFAULT 0,
  avatar_key            VARCHAR(80)     NULL,
  status                TINYINT         NOT NULL DEFAULT 1,
  roles                 INT UNSIGNED    NOT NULL DEFAULT 0,
  totp_secret_enc       VARBINARY(160)  NULL,
  totp_last_step        BIGINT          NOT NULL DEFAULT 0,
  profile_version       BIGINT UNSIGNED NOT NULL DEFAULT 1,
  username_changed_at   DATETIME(3)     NULL,
  registered_via        VARCHAR(64)     NOT NULL DEFAULT '',
  created_at            DATETIME(3)     NOT NULL,
  updated_at            DATETIME(3)     NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_public_sub (public_sub),
  UNIQUE KEY uq_users_username_norm (username_norm),
  KEY idx_users_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS user_tombstones (
  id           BINARY(16)  NOT NULL,
  public_sub   CHAR(22)    NOT NULL,
  deleted_at   DATETIME(3) NOT NULL,
  PRIMARY KEY (id),
  KEY idx_tomb_deleted (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS username_reservations (
  username_norm  VARCHAR(32)  NOT NULL,
  user_id        BINARY(16)   NOT NULL,
  expires_at     DATETIME(3)  NOT NULL,
  PRIMARY KEY (username_norm),
  KEY idx_resv_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS sso_sessions (
  id               BINARY(32)    NOT NULL,
  sid              CHAR(22)      NOT NULL,
  user_id          BINARY(16)    NOT NULL,
  auth_time        DATETIME(3)   NOT NULL,
  amr              VARCHAR(64)   NOT NULL,
  created_at       DATETIME(3)   NOT NULL,
  last_seen_at     DATETIME(3)   NOT NULL,
  idle_expires_at  DATETIME(3)   NOT NULL,
  abs_expires_at   DATETIME(3)   NOT NULL,
  ip               VARCHAR(45)   NOT NULL DEFAULT '',
  user_agent       VARCHAR(255)  NOT NULL DEFAULT '',
  revoked_at       DATETIME(3)   NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_sessions_sid (sid),
  KEY idx_sessions_user (user_id, revoked_at),
  KEY idx_sessions_expiry (idle_expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS clients (
  id                          VARCHAR(64)    NOT NULL,
  name                        VARCHAR(100)   NOT NULL,
  description                 VARCHAR(500)   NOT NULL DEFAULT '',
  logo_uri                    VARCHAR(500)   NOT NULL DEFAULT '',
  client_uri                  VARCHAR(500)   NOT NULL DEFAULT '',
  policy_uri                  VARCHAR(500)   NOT NULL DEFAULT '',
  tos_uri                     VARCHAR(500)   NOT NULL DEFAULT '',
  client_type                 TINYINT        NOT NULL,
  application_type            VARCHAR(10)    NOT NULL DEFAULT 'web',
  token_endpoint_auth_method  VARCHAR(32)    NOT NULL,
  secret_hash                 VARBINARY(32)  NULL,
  secret_rotated_at           DATETIME(3)    NULL,
  redirect_uris               JSON           NOT NULL,
  post_logout_redirect_uris   JSON           NOT NULL,
  grant_types                 JSON           NOT NULL,
  scopes                      VARCHAR(500)   NOT NULL,
  id_token_alg                VARCHAR(8)     NOT NULL DEFAULT 'RS256',
  subject_type                VARCHAR(10)    NOT NULL DEFAULT 'pairwise',
  sector_id                   VARCHAR(255)   NOT NULL DEFAULT '',
  first_party                 TINYINT(1)     NOT NULL DEFAULT 0,
  native_login                TINYINT(1)     NOT NULL DEFAULT 0,
  skip_consent                TINYINT(1)     NOT NULL DEFAULT 0,
  allow_registration          TINYINT(1)     NOT NULL DEFAULT 1,
  require_amr                 VARCHAR(16)    NOT NULL DEFAULT '',
  require_dpop                TINYINT(1)     NOT NULL DEFAULT 0,
  verified                    TINYINT(1)     NOT NULL DEFAULT 0,
  access_token_ttl_s          INT            NULL,
  webhook_url                 VARCHAR(500)   NOT NULL DEFAULT '',
  webhook_secret_enc          VARBINARY(128) NULL,
  webhook_events              JSON           NOT NULL,
  webhook_allow_insecure      TINYINT(1)     NOT NULL DEFAULT 0,
  webhook_cursor_seq          BIGINT         NOT NULL DEFAULT 0,
  webhook_attempts            INT            NOT NULL DEFAULT 0,
  webhook_next_attempt_at     DATETIME(3)    NULL,
  webhook_last_error          VARCHAR(500)   NOT NULL DEFAULT '',
  webhook_fail_since          DATETIME(3)    NULL,
  webhook_disabled_at         DATETIME(3)    NULL,
  backchannel_logout_uri      VARCHAR(500)   NOT NULL DEFAULT '',
  status                      TINYINT        NOT NULL DEFAULT 1,
  owner_user_id               BINARY(16)     NULL,
  rat_hash                    VARBINARY(32)  NULL,
  created_at                  DATETIME(3)    NOT NULL,
  updated_at                  DATETIME(3)    NOT NULL,
  PRIMARY KEY (id),
  KEY idx_clients_owner (owner_user_id),
  KEY idx_clients_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- One row per (user, client) that has ever received tokens; consented_scopes
-- is what the user explicitly approved on the consent screen.
CREATE TABLE IF NOT EXISTS grants (
  user_id           BINARY(16)    NOT NULL,
  client_id         VARCHAR(64)   NOT NULL,
  consented_scopes  VARCHAR(500)  NOT NULL DEFAULT '',
  created_at        DATETIME(3)   NOT NULL,
  updated_at        DATETIME(3)   NOT NULL,
  revoked_at        DATETIME(3)   NULL,
  PRIMARY KEY (user_id, client_id),
  KEY idx_grants_client (client_id, revoked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS session_clients (
  sid         CHAR(22)     NOT NULL,
  client_id   VARCHAR(64)  NOT NULL,
  created_at  DATETIME(3)  NOT NULL,
  PRIMARY KEY (sid, client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash              BINARY(32)     NOT NULL,
  client_id              VARCHAR(64)    NOT NULL,
  user_id                BINARY(16)     NOT NULL,
  sid                    CHAR(22)       NOT NULL,
  redirect_uri           VARCHAR(2000)  NOT NULL,
  scopes                 VARCHAR(500)   NOT NULL,
  resource               VARCHAR(500)   NOT NULL DEFAULT '',
  nonce                  VARCHAR(255)   NOT NULL DEFAULT '',
  code_challenge         VARCHAR(128)   NOT NULL DEFAULT '',
  code_challenge_method  VARCHAR(8)     NOT NULL DEFAULT '',
  dpop_jkt               VARCHAR(64)    NOT NULL DEFAULT '',
  auth_time              DATETIME(3)    NOT NULL,
  amr                    VARCHAR(64)    NOT NULL,
  expires_at             DATETIME(3)    NOT NULL,
  used_at                DATETIME(3)    NULL,
  family_id              BINARY(16)     NULL,
  PRIMARY KEY (code_hash),
  KEY idx_codes_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS refresh_families (
  id                 BINARY(16)     NOT NULL,
  client_id          VARCHAR(64)    NOT NULL,
  user_id            BINARY(16)     NOT NULL,
  sid                CHAR(22)       NULL,
  scopes             VARCHAR(500)   NOT NULL,
  resource           VARCHAR(500)   NOT NULL DEFAULT '',
  current_hash       BINARY(32)     NOT NULL,
  current_enc        VARBINARY(128) NULL,
  current_issued_at  DATETIME(3)    NOT NULL,
  generation         INT            NOT NULL DEFAULT 1,
  auth_time          DATETIME(3)    NOT NULL,
  amr                VARCHAR(64)    NOT NULL,
  dpop_jkt           VARCHAR(64)    NOT NULL DEFAULT '',
  created_at         DATETIME(3)    NOT NULL,
  idle_expires_at    DATETIME(3)    NOT NULL,
  abs_expires_at     DATETIME(3)    NOT NULL,
  last_used_at       DATETIME(3)    NOT NULL,
  last_ip            VARCHAR(45)    NOT NULL DEFAULT '',
  user_agent         VARCHAR(255)   NOT NULL DEFAULT '',
  revoked_at         DATETIME(3)    NULL,
  revoke_reason      VARCHAR(40)    NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  UNIQUE KEY uq_families_current (current_hash),
  KEY idx_families_user (user_id, revoked_at),
  KEY idx_families_sid (sid),
  KEY idx_families_expiry (idle_expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS refresh_token_history (
  token_hash  BINARY(32)   NOT NULL,
  family_id   BINARY(16)   NOT NULL,
  rotated_at  DATETIME(3)  NOT NULL,
  PRIMARY KEY (token_hash),
  KEY idx_rth_rotated (rotated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS signing_keys (
  kid           VARCHAR(32)     NOT NULL,
  alg           VARCHAR(8)      NOT NULL,
  private_enc   VARBINARY(4096) NOT NULL,
  public_jwk    JSON            NOT NULL,
  state         TINYINT         NOT NULL,
  created_at    DATETIME(3)     NOT NULL,
  activate_at   DATETIME(3)     NOT NULL,
  retired_at    DATETIME(3)     NULL,
  PRIMARY KEY (kid),
  KEY idx_keys_state (state)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS settings (
  k           VARCHAR(64)  NOT NULL,
  v           JSON         NOT NULL,
  updated_at  DATETIME(3)  NOT NULL,
  PRIMARY KEY (k)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Domain events. seq is assigned after commit by the single sequencer so that
-- readers using "seq > cursor" never skip a late-committing row.
CREATE TABLE IF NOT EXISTS outbox_events (
  id          BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
  seq         BIGINT UNSIGNED  NULL,
  event_type  VARCHAR(40)      NOT NULL,
  user_id     BINARY(16)       NULL,
  payload     JSON             NOT NULL,
  recipients  JSON             NOT NULL,
  created_at  DATETIME(3)      NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_outbox_seq (seq),
  KEY idx_outbox_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Per-recipient fan-out written by the sequencer; drives the changes feed,
-- SSE resume and ordered per-client webhook delivery.
CREATE TABLE IF NOT EXISTS client_events (
  client_id   VARCHAR(64)      NOT NULL,
  seq         BIGINT UNSIGNED  NOT NULL,
  event_id    BIGINT UNSIGNED  NOT NULL,
  user_id     BINARY(16)       NULL,
  PRIMARY KEY (client_id, seq),
  KEY idx_ce_user (client_id, user_id, seq),
  KEY idx_ce_seq (seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS webhook_dead_letters (
  id           BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
  client_id    VARCHAR(64)      NOT NULL,
  seq          BIGINT UNSIGNED  NOT NULL,
  event_id     BIGINT UNSIGNED  NOT NULL,
  attempts     INT              NOT NULL,
  last_error   VARCHAR(500)     NOT NULL,
  created_at   DATETIME(3)      NOT NULL,
  resolved_at  DATETIME(3)      NULL,
  PRIMARY KEY (id),
  KEY idx_dead_client (client_id, resolved_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS backchannel_jobs (
  id               BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
  client_id        VARCHAR(64)      NOT NULL,
  user_id          BINARY(16)       NOT NULL,
  sid              CHAR(22)         NOT NULL DEFAULT '',
  attempts         INT              NOT NULL DEFAULT 0,
  next_attempt_at  DATETIME(3)      NOT NULL,
  status           TINYINT          NOT NULL DEFAULT 0,
  last_error       VARCHAR(500)     NOT NULL DEFAULT '',
  created_at       DATETIME(3)      NOT NULL,
  PRIMARY KEY (id),
  KEY idx_bc_due (status, next_attempt_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS initial_access_tokens (
  token_hash   BINARY(32)    NOT NULL,
  note         VARCHAR(200)  NOT NULL DEFAULT '',
  created_by   BINARY(16)    NULL,
  uses_left    INT           NOT NULL DEFAULT 1,
  expires_at   DATETIME(3)   NOT NULL,
  created_at   DATETIME(3)   NOT NULL,
  PRIMARY KEY (token_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS audit_log (
  id               BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
  at               DATETIME(3)      NOT NULL,
  actor_user_id    BINARY(16)       NULL,
  actor_client_id  VARCHAR(64)      NOT NULL DEFAULT '',
  action           VARCHAR(64)      NOT NULL,
  target_type      VARCHAR(16)      NOT NULL DEFAULT '',
  target_id        VARCHAR(64)      NOT NULL DEFAULT '',
  ip               VARCHAR(45)      NOT NULL DEFAULT '',
  meta             JSON             NULL,
  PRIMARY KEY (id),
  KEY idx_audit_at (at),
  KEY idx_audit_actor (actor_user_id, at),
  KEY idx_audit_target (target_type, target_id, at),
  KEY idx_audit_action (action, at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
