package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;

import com.authcore.auth.support.IntegrationTest;

/**
 * F2: every log line of a request has the request's trace id, and a 500 answer names it,
 * so that its details can be found in the log.
 */
@ExtendWith(OutputCaptureExtension.class)
class TraceIdTests extends IntegrationTest {
    private static final Pattern TRACE_ID = Pattern.compile("\"traceId\":\"([0-9a-f]{32})\"");

    @Test
    void aFiveHundredNamesItsTraceIdAndTheLogHasIt(CapturedOutput output) throws Exception {
        String email = uniqueEmail();
        jdbc.execute("rename table one_time_tokens to one_time_tokens_hidden");
        String body;
        try {
            body = register(email, PASSWORD).andExpect(status().isInternalServerError())
                    .andReturn().getResponse().getContentAsString();
        } finally {
            jdbc.execute("rename table one_time_tokens_hidden to one_time_tokens");
        }

        Matcher traceId = TRACE_ID.matcher(body);
        assertThat(traceId.find()).as(body).isTrue();
        assertThat(output.getOut().lines().filter(line -> line.contains(traceId.group(1))))
                .anyMatch(line -> line.contains("ERROR"));
    }

    /** Other errors don't: their answers must stay the same for everyone (H2). */
    @Test
    void otherErrorsHaveNoTraceId() throws Exception {
        assertThat(login(uniqueEmail(), PASSWORD).andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString()).doesNotContain("traceId");
    }

    /** In production, log lines are JSON (one object per line) for a log collector. */
    @Test
    void productionLogsAreJson() throws Exception {
        PropertySource<?> prod = new YamlPropertySourceLoader()
                .load("prod", new ClassPathResource("application-prod.yml")).getFirst();

        assertThat(prod.getProperty("logging.structured.format.console")).isEqualTo("ecs");
    }
}
