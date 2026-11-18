-- V1: the schema as it was when Flyway was introduced (Phase 1).
--
-- It matches what Hibernate generated from the entities with ddl-auto=update, so a
-- database created that way has the same tables. Hibernate now only validates the
-- schema (ddl-auto=validate); every change from here on is a new migration.
--
-- The *_seq tables back @GeneratedValue(AUTO) ids: MySQL has no sequences, so
-- Hibernate emulates them with one-row tables. (M5 plans a switch to IDENTITY.)

create table users (
    id          integer      not null,
    first_name  varchar(255) not null,
    last_name   varchar(255),
    email       varchar(255) not null,
    password    varchar(255) not null,
    role        enum ('ADMIN', 'USER') not null,
    is_enabled  bit          not null,
    created_at  date         not null,
    updated_at  date         not null,
    primary key (id),
    constraint uk_users_email unique (email)
) engine = InnoDB;

create table users_seq (
    next_val bigint
) engine = InnoDB;
insert into users_seq (next_val) values (1);

create table refresh_tokens (
    id           integer       not null,
    user_id      integer,
    token        varchar(1000) not null,
    created_at   date          not null,
    expiry_date  datetime(6)   not null,
    primary key (id),
    constraint uk_refresh_tokens_user unique (user_id),
    constraint fk_refresh_tokens_user foreign key (user_id) references users (id)
) engine = InnoDB;

create table refresh_tokens_seq (
    next_val bigint
) engine = InnoDB;
insert into refresh_tokens_seq (next_val) values (1);

create table verification_tokens (
    id           integer       not null,
    user_id      integer,
    token        varchar(1000) not null,
    created_at   date          not null,
    expiry_date  datetime(6)   not null,
    primary key (id),
    constraint uk_verification_tokens_user unique (user_id),
    constraint fk_verification_tokens_user foreign key (user_id) references users (id)
) engine = InnoDB;

create table verification_tokens_seq (
    next_val bigint
) engine = InnoDB;
insert into verification_tokens_seq (next_val) values (1);

create table password_reset_otp (
    id           integer     not null,
    user_id      integer,
    otp          bigint      not null,
    created_at   date        not null,
    expiry_date  datetime(6) not null,
    primary key (id),
    constraint uk_password_reset_otp_user unique (user_id),
    constraint fk_password_reset_otp_user foreign key (user_id) references users (id)
) engine = InnoDB;

create table password_reset_otp_seq (
    next_val bigint
) engine = InnoDB;
insert into password_reset_otp_seq (next_val) values (1);

create table delete_account_otp (
    id           integer     not null,
    user_id      integer,
    otp          bigint      not null,
    created_at   date        not null,
    expiry_date  datetime(6) not null,
    primary key (id),
    constraint uk_delete_account_otp_user unique (user_id),
    constraint fk_delete_account_otp_user foreign key (user_id) references users (id)
) engine = InnoDB;

create table delete_account_otp_seq (
    next_val bigint
) engine = InnoDB;
insert into delete_account_otp_seq (next_val) values (1);
