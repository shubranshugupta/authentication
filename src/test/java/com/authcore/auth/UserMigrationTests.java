package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Test;
import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * V8 (M5) gives users AUTO_INCREMENT ids and timestamps with a time, and keeps everything
 * else. It needs rows from before V8, so it uses its own MySQL.
 */
class UserMigrationTests {

    @Test
    void usersKeepTheirIdsAndDatesAndNewOnesContinueAfterTheHighest() throws Exception {
        try (MySQLContainer mysql = new MySQLContainer(DockerImageName.parse("mysql:8.4"))) {
            mysql.start();
            migrate(mysql, "7");
            try (Connection connection = DriverManager.getConnection(mysql.getJdbcUrl(), mysql.getUsername(),
                    mysql.getPassword()); Statement sql = connection.createStatement()) {
                // Ids from users_seq have gaps: Hibernate reserved them 50 at a time.
                sql.execute("insert into users (id, first_name, email, password, role, is_enabled, created_at, updated_at)"
                        + " values (1, 'a', 'a@example.com', 'x', 'USER', 1, '2026-01-01', '2026-02-01'),"
                        + " (52, 'b', 'b@example.com', 'x', 'ADMIN', 1, '2026-03-01', '2026-03-01')");
                sql.execute("insert into user_sessions (user_id, ip, created_at, last_used_at, expires_at)"
                        + " values (52, '127.0.0.1', '2026-03-01', '2026-03-01', '2030-01-01')");
                sql.execute("insert into one_time_tokens values (1, 52, 'PASSWORD_RESET', 'hash', 0, '2026-01-01', '2030-01-01', null)");

                migrate(mysql, "8");

                assertThat(text(sql, "select concat(created_at, ' / ', updated_at) from users where id = 1"))
                        .isEqualTo("2026-01-01 00:00:00.000000 / 2026-02-01 00:00:00.000000");
                assertThat(number(sql, "select count(*) from information_schema.tables"
                        + " where table_schema = database() and table_name = 'users_seq'")).isZero();

                sql.execute("insert into users (first_name, email, password, role, is_enabled, created_at, updated_at)"
                        + " values ('c', 'c@example.com', 'x', 'USER', 0, now(6), now(6))");
                assertThat(number(sql, "select id from users where email = 'c@example.com'")).isEqualTo(53);

                // The foreign keys still point at users, and still cascade.
                sql.execute("delete from users where id = 52");
                assertThat(number(sql, "select count(*) from user_sessions")).isZero();
                assertThat(number(sql, "select count(*) from one_time_tokens")).isZero();
                assertThat(number(sql, "select count(*) from information_schema.referential_constraints"
                        + " where constraint_schema = database() and referenced_table_name = 'users'")).isEqualTo(2);
            }
        }
    }

    private static int number(Statement sql, String query) throws Exception {
        try (ResultSet row = sql.executeQuery(query)) {
            row.next();
            return row.getInt(1);
        }
    }

    private static String text(Statement sql, String query) throws Exception {
        try (ResultSet row = sql.executeQuery(query)) {
            row.next();
            return row.getString(1);
        }
    }

    private static void migrate(MySQLContainer mysql, String version) {
        Flyway.configure()
                .dataSource(mysql.getJdbcUrl(), mysql.getUsername(), mysql.getPassword())
                .locations("classpath:db/migration")
                .target(MigrationVersion.fromVersion(version))
                .load()
                .migrate();
    }
}
