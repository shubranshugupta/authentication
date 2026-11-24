package com.authcore.auth.exception.handler;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Errors the application doesn't expect: 500, with the details only in the server log (H2). */
class GlobalExceptionHandlerTests {
    private static final String SECRET = "jdbc:mysql://internal-host/auth";

    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new FailingController())
            .setControllerAdvice(new GlobalExceptionHandler()).build();

    @Test
    void unexpectedException() throws Exception {
        expectGeneric500("/unexpected");
    }

    @Test
    void anErrorIsHandledToo() throws Exception {
        expectGeneric500("/error-thrown");
    }

    /** The database failing during login is the server's fault, not a wrong password. */
    @Test
    void loginThatCouldNotBeChecked() throws Exception {
        expectGeneric500("/login-broken");
    }

    @Test
    void springsOwnServerErrors() throws Exception {
        expectGeneric500("/not-writable");
    }

    private void expectGeneric500(String path) throws Exception {
        mvc.perform(get(path))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.code").value("INTERNAL_ERROR"))
                .andExpect(jsonPath("$.status").value(500))
                .andExpect(jsonPath("$.detail").value("An unexpected error occurred."))
                .andExpect(content().string(not(containsString(SECRET))));
    }

    @RestController
    static class FailingController {
        @GetMapping("/unexpected")
        void unexpected() {
            throw new IllegalStateException(SECRET);
        }

        @GetMapping("/error-thrown")
        void error() {
            throw new StackOverflowError(SECRET);
        }

        @GetMapping("/login-broken")
        void loginBroken() {
            throw new InternalAuthenticationServiceException(SECRET);
        }

        @GetMapping("/not-writable")
        void notWritable() {
            throw new HttpMessageNotWritableException(SECRET);
        }
    }
}
