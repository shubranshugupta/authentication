-- V8 (M5): users get database-generated ids, and timestamps with a time of day.
--
-- Until now Hibernate took ids from the one-row table users_seq (@GeneratedValue(AUTO)),
-- which costs an extra query and lock per registration. MySQL's AUTO_INCREMENT continues
-- after the highest existing id.
--
-- created_at and updated_at were dates without a time; existing ones become midnight (UTC).

-- MySQL refuses to change a column that foreign keys point to (error 1833) unless the
-- checks are off. The column keeps its type, so the foreign keys stay valid.
set foreign_key_checks = 0;
alter table users
    modify id         integer     not null auto_increment,
    modify created_at datetime(6) not null,
    modify updated_at datetime(6) not null;
set foreign_key_checks = 1;

drop table users_seq;
