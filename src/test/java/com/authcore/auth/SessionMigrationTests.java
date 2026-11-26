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
 * V5 and V6 keep the users and their codes, and drop the old refresh tokens (C2, H6). It
 * needs rows from before V5, so it uses its own MySQL.
 */
class SessionMigrationTests {

    @Test
    void usersAndCodesAreKeptAndEveryoneHasToLogInAgain() throws Exception {
        try (MySQLContainer mysql = new MySQLContainer(DockerImageName.parse("mysql:8.4"))) {
            mysql.start();
            migrate(mysql, "4");
            try (Connection connection = DriverManager.getConnection(mysql.getJdbcUrl(), mysql.getUsername(),
                    mysql.getPassword()); Statement sql = connection.createStatement()) {
                sql.execute("insert into users (id, first_name, email, password, role, is_enabled, created_at, updated_at)"
                        + " values (1, 'a', 'a@example.com', 'x', 'USER', 1, '2026-01-01', '2026-01-01')");
                sql.execute("insert into refresh_tokens values (1, 1, 'plain-text-token', '2026-01-01', '2030-01-01')");
                sql.execute("insert into one_time_tokens values (1, 1, 'PASSWORD_RESET', 'hash', 0, '2026-01-01', '2030-01-01', null)");

                migrate(mysql, "6");

                assertThat(number(sql, "select count(*) from users where token_version = 0 and password = 'x'")).isEqualTo(1);
                assertThat(number(sql, "select count(*) from one_time_tokens")).isEqualTo(1);
                assertThat(number(sql, "select count(*) from refresh_tokens")).isZero();
                assertThat(number(sql, "select count(*) from user_sessions")).isZero();
                assertThat(number(sql, "select count(*) from information_schema.tables"
                        + " where table_schema = database() and table_name = 'refresh_tokens_seq'")).isZero();
            }
        }
    }

    private static int number(Statement sql, String query) throws Exception {
        try (ResultSet row = sql.executeQuery(query)) {
            row.next();
            return row.getInt(1);
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
