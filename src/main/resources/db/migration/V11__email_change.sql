-- V11: changing the email (F5).
--
-- A code or link can be for an address other than the account's: the new address, for the
-- code that confirms it, and the old address, for the link that changes it back. That
-- address is where the email goes, and what the account gets once the code or link is used.
--
-- The index is for registration and email changes, which must not take an address that
-- an unused undo link can still change an account back to.

alter table one_time_tokens add column email varchar(255) null;

create index ix_one_time_tokens_email on one_time_tokens (email);
