-- Customizable "Sign in with SSO" button.
--
-- NULL/empty text falls back to the default "Sign in with SSO" label. The
-- optional SVG logo is stored as a file at `{data_dir}/sso_logo.svg` (mirroring
-- the company logo at `{data_dir}/logo.png`), not in the DB.
ALTER TABLE auth_config ADD COLUMN sso_button_text TEXT;
