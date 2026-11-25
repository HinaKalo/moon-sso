-- Profile version of the last ID token issued to a family: refreshes only
-- include a new ID token when the profile changed (saves an RSA signature).
ALTER TABLE refresh_families ADD COLUMN id_pv BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER generation;
