package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Test;
import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * V2 lowercases the emails stored before they were normalized (H1). It needs a database
 * with rows from before V2, so it uses its own MySQL instead of the shared one.
 */
class EmailMigrationTests {

    @Test
    void v2LowercasesExistingEmailsAndChangesNothingElse() throws Exception {
        try (MySQLContainer mysql = new MySQLContainer(DockerImageName.parse("mysql:8.4"))) {
            mysql.start();
            migrate(mysql, "1");
            execute(mysql, """
                    insert into users (id, first_name, email, password, role, is_enabled, created_at, updated_at)
                    values (1, 'Jane', 'Jane.Doe@Example.COM', 'HashA', 'ADMIN', 1, '2026-01-01', '2026-01-02'),
                           (2, 'John', 'john@example.com', 'HashB', 'USER', 0, '2026-01-01', '2026-01-02')
                    """);

            migrate(mysql, "2");

            assertThat(users(mysql)).containsExactly(
                    "Jane|jane.doe@example.com|HashA|ADMIN|2026-01-02",
                    "John|john@example.com|HashB|USER|2026-01-02");
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

    private static void execute(MySQLContainer mysql, String sql) throws SQLException {
        try (Connection connection = connect(mysql); Statement statement = connection.createStatement()) {
            statement.executeUpdate(sql);
        }
    }

    private static List<String> users(MySQLContainer mysql) throws SQLException {
        List<String> users = new ArrayList<>();
        try (Connection connection = connect(mysql);
                Statement statement = connection.createStatement();
                ResultSet row = statement.executeQuery(
                        "select concat_ws('|', first_name, email, password, role, updated_at) from users order by id")) {
            while (row.next())
                users.add(row.getString(1));
        }
        return users;
    }

    private static Connection connect(MySQLContainer mysql) throws SQLException {
        return DriverManager.getConnection(mysql.getJdbcUrl(), mysql.getUsername(), mysql.getPassword());
    }
}
