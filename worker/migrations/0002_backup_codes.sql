-- Backup codes for password reset without email.
ALTER TABLE users ADD COLUMN backup_codes TEXT;
