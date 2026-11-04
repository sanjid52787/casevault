-- V7: Add optional display_name column for admin-provisioned accounts.
ALTER TABLE users ADD COLUMN display_name VARCHAR(160);

