package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;

import com.authcore.auth.support.IntegrationTest;

class AuthApplicationTests extends IntegrationTest {

	@Autowired
	private Environment environment;

	@Test
	void contextLoads() {
	}

	@Test
	void flywayCreatesTheSchemaAndHibernateOnlyValidatesIt() {
		assertThat(environment.getProperty("spring.jpa.hibernate.ddl-auto")).isEqualTo("validate");

		List<String> appliedVersions = jdbc.queryForList(
				"select version from flyway_schema_history where success = 1 and version is not null order by installed_rank",
				String.class);
		assertThat(appliedVersions).startsWith("1");

		List<String> tables = jdbc.queryForList(
				"select table_name from information_schema.tables where table_schema = database()",
				String.class);
		assertThat(tables).contains("users", "refresh_tokens", "one_time_tokens");
		assertThat(tables).doesNotContain("verification_tokens", "password_reset_otp", "delete_account_otp");
	}

	/** OneTimeTokenService relies on it. */
	@Test
	void transactionsReadWhatIsCommitted() {
		assertThat(jdbc.queryForObject("select @@transaction_isolation", String.class)).isEqualTo("READ-COMMITTED");
	}
}
