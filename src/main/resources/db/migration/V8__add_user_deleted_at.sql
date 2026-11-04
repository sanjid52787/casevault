-- V8: Add optional deleted_at column for soft deletion and anonymisation of user accounts.
ALTER TABLE users ADD COLUMN deleted_at TIMESTAMP WITH TIME ZONE;

