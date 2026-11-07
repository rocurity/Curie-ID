-- Email change: the new address waits here until its code is confirmed.
ALTER TABLE users ADD COLUMN pending_email TEXT;
