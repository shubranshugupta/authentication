-- V13: signing in with Google (F5).
--
-- A Google account is known by its subject ("sub"), which never changes, not by its email,
-- which can. One user can have one Google account; a Google account belongs to one user.

create table social_identities (
    id            bigint       not null auto_increment,
    user_id       integer      not null,
    provider      varchar(32)  not null,
    subject       varchar(255) not null,
    created_at    datetime(6)  not null,
    last_login_at datetime(6)  not null,
    primary key (id),
    constraint uk_social_identities_provider_subject unique (provider, subject),
    constraint uk_social_identities_user_provider unique (user_id, provider),
    constraint fk_social_identities_user foreign key (user_id) references users (id) on delete cascade
) engine = InnoDB;
