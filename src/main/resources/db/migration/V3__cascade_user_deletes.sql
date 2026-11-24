-- V3: deleting a user deletes their token rows in the database (A4).
--
-- The User entity used to do this through links to every token table. Without those
-- links, the foreign keys do it: the same constraints as before, plus ON DELETE CASCADE.
--
-- The old constraint names are looked up, because only databases created by V1 have
-- V1's names. One created earlier by Hibernate (and baselined) has generated ones.

set @drop_fk = (select concat('alter table refresh_tokens drop foreign key `', constraint_name, '`')
    from information_schema.key_column_usage
    where table_schema = database() and table_name = 'refresh_tokens'
      and column_name = 'user_id' and referenced_table_name = 'users');
prepare drop_fk from @drop_fk;
execute drop_fk;
deallocate prepare drop_fk;
alter table refresh_tokens
    add constraint fk_refresh_tokens_user foreign key (user_id) references users (id) on delete cascade;

set @drop_fk = (select concat('alter table verification_tokens drop foreign key `', constraint_name, '`')
    from information_schema.key_column_usage
    where table_schema = database() and table_name = 'verification_tokens'
      and column_name = 'user_id' and referenced_table_name = 'users');
prepare drop_fk from @drop_fk;
execute drop_fk;
deallocate prepare drop_fk;
alter table verification_tokens
    add constraint fk_verification_tokens_user foreign key (user_id) references users (id) on delete cascade;

set @drop_fk = (select concat('alter table password_reset_otp drop foreign key `', constraint_name, '`')
    from information_schema.key_column_usage
    where table_schema = database() and table_name = 'password_reset_otp'
      and column_name = 'user_id' and referenced_table_name = 'users');
prepare drop_fk from @drop_fk;
execute drop_fk;
deallocate prepare drop_fk;
alter table password_reset_otp
    add constraint fk_password_reset_otp_user foreign key (user_id) references users (id) on delete cascade;

set @drop_fk = (select concat('alter table delete_account_otp drop foreign key `', constraint_name, '`')
    from information_schema.key_column_usage
    where table_schema = database() and table_name = 'delete_account_otp'
      and column_name = 'user_id' and referenced_table_name = 'users');
prepare drop_fk from @drop_fk;
execute drop_fk;
deallocate prepare drop_fk;
alter table delete_account_otp
    add constraint fk_delete_account_otp_user foreign key (user_id) references users (id) on delete cascade;
