-- V14: addresses not to email any more (M7e). SES reports a permanent bounce (the address
-- doesn't exist) or a complaint (the recipient marked an email as spam) through SNS; going
-- on emailing them hurts the sender's reputation, and SES can pause sending for it.
-- An admin can take an address off the list.

create table email_suppressions (
    id         bigint       not null auto_increment,
    email      varchar(255) not null,
    reason     varchar(16)  not null,
    detail     varchar(64),
    created_at datetime(6)  not null,
    primary key (id),
    constraint uk_email_suppressions_email unique (email)
) engine = InnoDB;
