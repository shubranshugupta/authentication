-- V4: one table for every code and link sent by email (A1), instead of one per type.
--
-- Holds only hashes (C1). The old tables hold plain codes, which can't be carried over:
-- whoever has an unused code or link from before this has to request a new one.

create table one_time_tokens (
    id          bigint      not null auto_increment,
    user_id     integer     not null,
    purpose     varchar(32) not null,
    token_hash  varchar(64) not null,
    attempts    integer     not null,
    issued_at   datetime(6) not null,
    expires_at  datetime(6) not null,
    consumed_at datetime(6),
    primary key (id),
    constraint uk_one_time_tokens_user_purpose unique (user_id, purpose),
    constraint uk_one_time_tokens_hash unique (token_hash),
    constraint fk_one_time_tokens_user foreign key (user_id) references users (id) on delete cascade
) engine = InnoDB;

drop table verification_tokens;
drop table password_reset_otp;
drop table delete_account_otp;
drop table if exists verification_tokens_seq;
drop table if exists password_reset_otp_seq;
drop table if exists delete_account_otp_seq;
