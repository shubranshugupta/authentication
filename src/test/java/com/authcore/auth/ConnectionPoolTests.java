package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.authcore.auth.support.IntegrationTest;
import com.zaxxer.hikari.HikariDataSource;

/** M3: the database connection pool's size and timeouts come from application.yml. */
class ConnectionPoolTests extends IntegrationTest {

    @Autowired
    private DataSource dataSource;

    @Test
    void thePoolIsLimitedAndRequestsDoNotWaitLongForAConnection() throws Exception {
        HikariDataSource pool = dataSource.unwrap(HikariDataSource.class);

        assertThat(pool.getMaximumPoolSize()).isEqualTo(10);
        assertThat(pool.getConnectionTimeout()).isEqualTo(5_000);
        assertThat(pool.getKeepaliveTime()).isEqualTo(300_000);
    }
}
