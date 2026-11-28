-- V12: two-factor authentication with an authenticator app (TOTP, RFC 6238), F5.
--
-- totp_credentials: one per user. The secret is encrypted (AES-GCM, TOTP_ENCRYPTION_KEY),
-- so a copy of the database alone can't produce codes. Until enabled_at is set, it's a
-- setup the user hasn't confirmed with a code yet. last_used_step stops a code from being
-- used twice. failed_attempts and last_failed_at limit guesses here, not in Redis, so that
-- they're limited even while Redis is down.
--
-- recovery_codes: ten per user, each usable once, stored as keyed hashes.

create table totp_credentials (
    user_id         integer       not null,
    secret          varbinary(64) not null,
    created_at      datetime(6)   not null,
    enabled_at      datetime(6),
    last_used_step  bigint        not null,
    failed_attempts integer       not null,
    last_failed_at  datetime(6),
    primary key (user_id),
    constraint fk_totp_credentials_user foreign key (user_id) references users (id) on delete cascade
) engine = InnoDB;

create table recovery_codes (
    id        bigint      not null auto_increment,
    user_id   integer     not null,
    code_hash varchar(64) not null,
    used_at   datetime(6),
    primary key (id),
    constraint uk_recovery_codes_user_hash unique (user_id, code_hash),
    constraint fk_recovery_codes_user foreign key (user_id) references users (id) on delete cascade
) engine = InnoDB;
