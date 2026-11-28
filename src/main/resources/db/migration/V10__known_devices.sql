-- V10 (F5): the browsers and apps each user has logged in from, so that a login from a new
-- one can be emailed to the owner. A device is a random id in a cookie; only its SHA-256
-- hash is stored. A device unseen for 90 days counts as new again, and the cleanup job
-- deletes it.
create table known_devices (
    id           bigint      not null auto_increment,
    user_id      integer     not null,
    device_hash  varchar(64) not null,
    created_at   datetime(6) not null,
    last_seen_at datetime(6) not null,
    primary key (id),
    constraint uk_known_devices_user_device unique (user_id, device_hash),
    constraint fk_known_devices_user foreign key (user_id) references users (id) on delete cascade
) engine = InnoDB;

create index ix_known_devices_last_seen_at on known_devices (last_seen_at);
