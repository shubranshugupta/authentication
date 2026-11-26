package com.authcore.auth.common;

import java.util.List;

import lombok.Getter;

/** Settings the app can't run without are missing. See {@link RequiredSettings}. */
@Getter
public class MissingSettingsException extends RuntimeException {
    private final List<String> names;

    public MissingSettingsException(List<String> names) {
        super("Missing settings: " + String.join(", ", names));
        this.names = List.copyOf(names);
    }
}
