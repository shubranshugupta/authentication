-- V9 (M5): the cleanup jobs look rows up by when they expire or were used. Without these
-- indexes, every run would read the whole table.
create index ix_user_sessions_expires_at on user_sessions (expires_at);
create index ix_refresh_tokens_used_at on refresh_tokens (used_at);
create index ix_one_time_tokens_expires_at on one_time_tokens (expires_at);
