-- Every refresh family remembers the device/browser session it came from.
-- offline=1 families (offline_access) survive the end of that session.
ALTER TABLE refresh_families ADD COLUMN offline TINYINT(1) NOT NULL DEFAULT 0 AFTER sid;
