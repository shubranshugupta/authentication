package com.authcore.auth.common;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;

/**
 * Stops the startup when a setting listed in {@code auth.required-settings} is missing or
 * empty, and names all of them at once (M3). application-prod.yml lists them.
 *
 * <p>Without this, a missing DB_HOST, REDIS_HOST or MAIL_HOST is passed on as the text
 * "${DB_HOST}", and only fails at the first request that needs it.
 *
 * <p>Runs before any bean is created, so it's registered in META-INF/spring.factories
 * rather than being a bean itself.
 */
public class RequiredSettings implements EnvironmentPostProcessor, Ordered {
    static final String LIST = "auth.required-settings";
    /** Needed only while emails go over SMTP, not with MAIL_TRANSPORT=ses. */
    static final String SMTP_LIST = "auth.required-smtp-settings";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        Binder binder = Binder.get(environment);
        List<String> required = new ArrayList<>(binder.bind(LIST, Bindable.listOf(String.class)).orElse(List.of()));
        if (!"ses".equalsIgnoreCase(environment.getProperty("auth.mail.transport", "smtp").strip()))
            required.addAll(binder.bind(SMTP_LIST, Bindable.listOf(String.class)).orElse(List.of()));
        List<String> missing = required.stream()
                .map(String::strip)
                .filter(name -> !name.isEmpty())
                .filter(name -> {
                    String value = environment.getProperty(name);
                    return value == null || value.isBlank();
                })
                .toList();
        if (!missing.isEmpty())
            throw new MissingSettingsException(missing);
    }

    /** After the application*.yml files and the active profiles are known. */
    @Override
    public int getOrder() {
        return ConfigDataEnvironmentPostProcessor.ORDER + 1;
    }
}
