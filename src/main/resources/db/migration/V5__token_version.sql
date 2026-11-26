-- V5: a version number in every access token (H6).
--
-- Access tokens carry their user's token_version. Raising it makes every token issued so
-- far stop working, e.g. after a password reset.
alter table users add column token_version integer not null default 0;
