-- V7: admins can lock an account. Not the same as is_enabled, which means that the email
-- was verified.
alter table users add column locked_at datetime(6);
