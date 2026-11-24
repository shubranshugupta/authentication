package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Test;
import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * V4 replaces the three token tables by one (A1) without touching users and sessions. It
 * needs rows from before V4, so it uses its own MySQL.
 */
class OneTimeTokenMigrationTests {

    @Test
    void v4ReplacesTheTokenTablesAndKeepsUsersAndSessions() throws Exception {
        try (MySQLContainer mysql = new MySQLContainer(DockerImageName.parse("mysql:8.4"))) {
            mysql.start();
            migrate(mysql, "3");
            try (Connection connection = DriverManager.getConnection(mysql.getJdbcUrl(), mysql.getUsername(),
                    mysql.getPassword()); Statement sql = connection.createStatement()) {
                sql.execute("insert into users (id, first_name, email, password, role, is_enabled, created_at, updated_at)"
                        + " values (1, 'a', 'a@example.com', 'x', 'USER', 1, '2026-01-01', '2026-01-01')");
                for (String table : List.of("refresh_tokens", "verification_tokens", "password_reset_otp", "delete_account_otp"))
                    sql.execute("insert into " + table + " values (1, 1, '123456', '2026-01-01', '2030-01-01')");

                migrate(mysql, "4");

                assertThat(tables(sql)).containsExactlyInAnyOrder("flyway_schema_history", "users", "users_seq",
                        "refresh_tokens", "refresh_tokens_seq", "one_time_tokens");
                assertThat(count(sql, "users")).isEqualTo(1);
                assertThat(count(sql, "refresh_tokens")).isEqualTo(1);
                assertThat(count(sql, "one_time_tokens")).isZero();
            }
        }
    }

    private static List<String> tables(Statement sql) throws Exception {
        List<String> tables = new ArrayList<>();
        try (ResultSet row = sql.executeQuery(
                "select table_name from information_schema.tables where table_schema = database()")) {
            while (row.next())
                tables.add(row.getString(1));
        }
        return tables;
    }

    private static int count(Statement sql, String table) throws Exception {
        try (ResultSet row = sql.executeQuery("select count(*) from " + table)) {
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
