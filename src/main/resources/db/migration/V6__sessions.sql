-- V6: one session per login, so that each device has its own (C2).
--
-- The old table had one refresh token per user, shared by every device and stored in plain
-- text. Those tokens aren't carried over: everyone has to log in again.

drop table refresh_tokens;
drop table if exists refresh_tokens_seq;

create table user_sessions (
    id           bigint      not null auto_increment,
    user_id      integer     not null,
    device       varchar(255),
    ip           varchar(45) not null,
    created_at   datetime(6) not null,
    last_used_at datetime(6) not null,
    expires_at   datetime(6) not null,
    primary key (id),
    constraint fk_user_sessions_user foreign key (user_id) references users (id) on delete cascade
) engine = InnoDB;

-- Every refresh replaces the session's token. The used ones stay until the session ends:
-- if one shows up again, somebody has a copy of it.
create table refresh_tokens (
    id         bigint      not null auto_increment,
    session_id bigint      not null,
    token_hash varchar(64) not null,
    created_at datetime(6) not null,
    used_at    datetime(6),
    primary key (id),
    constraint uk_refresh_tokens_hash unique (token_hash),
    constraint fk_refresh_tokens_session foreign key (session_id) references user_sessions (id) on delete cascade
) engine = InnoDB;
