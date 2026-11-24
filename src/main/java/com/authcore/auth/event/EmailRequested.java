package com.authcore.auth.event;

import java.util.Map;

/**
 * Asks for an email to be sent. Carries plain values, never entities.
 *
 * @param template name of a Thymeleaf template in src/main/resources/templates
 * @param vars     the template's variables
 */
public record EmailRequested(String to, String subject, String template, Map<String, Object> vars) {
    /** Leaves out vars: they hold tokens and codes, which logs must not contain (H2). */
    @Override
    public String toString() {
        return "EmailRequested[subject=" + subject + ", template=" + template + "]";
    }
}
