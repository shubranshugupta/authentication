package com.authcore.auth.common;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class EmailAddressesTests {
    @Test
    void normalizingTrimsAndLowercases() {
        assertThat(EmailAddresses.normalize("  Jane@Example.COM ")).isEqualTo("jane@example.com");
    }

    @Test
    void maskingKeepsTheFirstLetterAndTheDomain() {
        assertThat(EmailAddresses.mask("jane@example.com")).isEqualTo("j***@example.com");
        assertThat(EmailAddresses.mask("j@example.com")).isEqualTo("j***@example.com");
        // The last @ is the one before the domain.
        assertThat(EmailAddresses.mask("\"a@b\"@example.com")).isEqualTo("\"***@example.com");
    }

    @Test
    void anythingWithoutALocalPartIsMaskedCompletely() {
        assertThat(EmailAddresses.mask("@example.com")).isEqualTo("***");
        assertThat(EmailAddresses.mask("no-at-sign")).isEqualTo("***");
    }
}
