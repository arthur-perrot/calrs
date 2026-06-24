-- Gravatar support.
--
-- Org-wide toggle (admin): when enabled, Gravatar becomes the default avatar
-- source for users who have not explicitly opted into the internal system.
ALTER TABLE auth_config ADD COLUMN gravatar_enabled INTEGER NOT NULL DEFAULT 0;

-- Per-user avatar source preference:
--   NULL       = follow the org default (Gravatar when enabled, else internal)
--   'gravatar' = always use Gravatar (when org allows it)
--   'internal' = always use the internally uploaded avatar / initials
ALTER TABLE users ADD COLUMN avatar_source TEXT;
