package com.authcore.auth.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.env.MockEnvironment;

import com.authcore.auth.AuthApplication;

/** M3: a missing setting stops the startup, instead of failing at the first request. */
@ExtendWith(OutputCaptureExtension.class)
class RequiredSettingsTests {

    @Test
    void namesEveryMissingOrEmptySettingAtOnce() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty(RequiredSettings.LIST, "DB_HOST, DB_USER, REDIS_HOST, MAIL_FROM")
                .withProperty("DB_HOST", "db.internal")
                .withProperty("REDIS_HOST", "  ");

        assertThatThrownBy(() -> check(environment))
                .isInstanceOf(MissingSettingsException.class)
                .hasMessage("Missing settings: DB_USER, REDIS_HOST, MAIL_FROM");
    }

    @Test
    void nothingIsCheckedWithoutAList() {
        assertThatNoException().isThrownBy(() -> check(new MockEnvironment()));
    }

    @Test
    void startsWhenEverythingIsSet() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty(RequiredSettings.LIST, "DB_HOST,DB_USER")
                .withProperty("DB_HOST", "db.internal")
                .withProperty("DB_USER", "auth");

        assertThatNoException().isThrownBy(() -> check(environment));
    }

    /** The settings that production can't do without, and that have no default. */
    @Test
    void theProdProfileListsItsSettingsWithoutDefaults() throws Exception {
        StandardEnvironment environment = new StandardEnvironment();
        new YamlPropertySourceLoader().load("prod", new ClassPathResource("application-prod.yml"))
                .forEach(environment.getPropertySources()::addLast);

        assertThat(Binder.get(environment).bind(RequiredSettings.LIST, Bindable.listOf(String.class)).get())
                .containsExactlyInAnyOrder("DB_HOST", "DB_DATABASE", "DB_USER", "DB_PASSWORD",
                        "REDIS_HOST", "REDIS_PASSWORD", "MAIL_FROM", "JWT_SECRET_KEY", "TOTP_ENCRYPTION_KEY",
                        "FRONTEND_URL");
        assertThat(Binder.get(environment).bind(RequiredSettings.SMTP_LIST, Bindable.listOf(String.class)).get())
                .containsExactlyInAnyOrder("MAIL_HOST", "MAIL_USERNAME", "MAIL_PASSWORD");
    }

    /** M7e: sending through the SES API needs no SMTP server. */
    @Test
    void theSmtpSettingsAreNeededOnlyForSmtp() {
        MockEnvironment smtp = new MockEnvironment()
                .withProperty(RequiredSettings.LIST, "MAIL_FROM")
                .withProperty(RequiredSettings.SMTP_LIST, "MAIL_HOST, MAIL_PASSWORD")
                .withProperty("MAIL_FROM", "noreply@example.com");
        assertThatThrownBy(() -> check(smtp)).hasMessage("Missing settings: MAIL_HOST, MAIL_PASSWORD");

        assertThatNoException().isThrownBy(() -> check(smtp.withProperty("auth.mail.transport", "ses")));
        assertThatThrownBy(() -> check(smtp.withProperty("auth.mail.transport", " SMTP ")))
                .isInstanceOf(MissingSettingsException.class);
    }

    /** Registered in spring.factories: it runs before anything connects anywhere. */
    @Test
    void aRealStartupStopsWithAShortMessage(CapturedOutput output) {
        SpringApplication application = new SpringApplication(AuthApplication.class);
        application.setAdditionalProfiles("prod");

        assertThatThrownBy(() -> application.run("--" + RequiredSettings.LIST + "=SURELY_NOT_SET_AUTHCORE_SETTING"))
                .isInstanceOf(MissingSettingsException.class);
        assertThat(output).contains("APPLICATION FAILED TO START")
                .contains("These settings are missing or empty: SURELY_NOT_SET_AUTHCORE_SETTING");
    }

    private static void check(MockEnvironment environment) {
        new RequiredSettings().postProcessEnvironment(environment, new SpringApplication());
    }
}
