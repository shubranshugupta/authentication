package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Test;
import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * V3 makes deleting a user delete their tokens in the database (A4), on databases
 * created by V1 and on ones created earlier by Hibernate, whose constraints have
 * generated names. It needs rows from before V3, so it uses its own MySQL.
 */
class CascadeMigrationTests {
    private static final List<String> TOKEN_TABLES = List.of(
            "refresh_tokens", "verification_tokens", "password_reset_otp", "delete_account_otp");

    @Test
    void deletingAUserDeletesTheirTokensAndNobodyElses() throws Exception {
        try (MySQLContainer mysql = new MySQLContainer(DockerImageName.parse("mysql:8.4"))) {
            mysql.start();
            migrate(mysql, "2");
            try (Connection connection = DriverManager.getConnection(mysql.getJdbcUrl(), mysql.getUsername(),
                    mysql.getPassword()); Statement sql = connection.createStatement()) {
                // As in a database Hibernate created: other constraint names.
                for (String table : TOKEN_TABLES) {
                    sql.execute("alter table " + table + " drop foreign key fk_" + table + "_user");
                    sql.execute("alter table " + table + " add constraint FKgenerated_" + table
                            + " foreign key (user_id) references users (id)");
                }
                for (int id = 1; id <= 2; id++) {
                    sql.execute("insert into users (id, first_name, email, password, role, is_enabled, created_at, updated_at)"
                            + " values (" + id + ", 'a', 'user" + id + "@example.com', 'x', 'USER', 1, '2026-01-01', '2026-01-01')");
                    for (String table : TOKEN_TABLES)
                        sql.execute("insert into " + table + " values ("
                                + id + ", " + id + ", '123456', '2026-01-01', '2030-01-01')");
                }

                migrate(mysql, "3");

                for (String table : TOKEN_TABLES)
                    assertThat(count(sql, table)).as(table + " keeps its rows").isEqualTo(2);

                sql.execute("delete from users where id = 1");

                for (String table : TOKEN_TABLES) {
                    assertThat(count(sql, table)).as(table).isEqualTo(1);
                    assertThat(count(sql, table + " where user_id = 2")).as(table).isEqualTo(1);
                }
            }
        }
    }

    private static int count(Statement sql, String from) throws Exception {
        try (ResultSet row = sql.executeQuery("select count(*) from " + from)) {
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
