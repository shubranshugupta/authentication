package com.authcore.auth.common;

import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

/** Prints missing settings as a short "APPLICATION FAILED TO START" message, without a stack trace. */
public class MissingSettingsFailureAnalyzer extends AbstractFailureAnalyzer<MissingSettingsException> {

    @Override
    protected FailureAnalysis analyze(Throwable rootFailure, MissingSettingsException cause) {
        return new FailureAnalysis(
                "These settings are missing or empty: " + String.join(", ", cause.getNames()),
                "Set them as environment variables (see env.properties.example and README.md).",
                cause);
    }
}
