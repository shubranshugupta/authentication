package com.authcore.auth.security;

import java.util.List;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.security.autoconfigure.actuate.web.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.social.GoogleSignIn;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {
    /** Everything else needs a login. */
    static final RequestMatcher PUBLIC = PathPatternRequestMatcher.pathPattern("/api/v1/auth/**");
    /** From other services (SNS), which prove who they are by a signature, not a login. */
    static final RequestMatcher WEBHOOKS = PathPatternRequestMatcher.pathPattern("/api/v1/webhooks/**");

    /** The API description and Swagger UI (F3); prod turns them off by default. */
    private static final String[] API_DOCS = { "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html" };

    private final JwtAuthFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final AuthConfigProperties authConfigProperties;
    private final DelegatedAuthenticationEntryPoint authEntryPoint;
    /** Only when GOOGLE_CLIENT_ID is set. */
    private final ObjectProvider<GoogleSignIn> googleSignIn;

    /**
     * Actuator answers on its own port only (management.server.port), which must not be
     * reachable from outside. On the API port, the same paths would need a login.
     */
    @Value("${management.server.port:${server.port:8080}}")
    private int managementPort;

    @Value("${server.port:8080}")
    private int serverPort;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // 0 is a random port (in tests), different from the other one.
        if (managementPort == serverPort && managementPort != 0)
            throw new IllegalStateException("MANAGEMENT_PORT must differ from SERVER_PORT: "
                    + "the metrics would be public on the API port.");
        http.csrf(csrf -> csrf
                .disable())
                // Uses the corsConfigurationSource bean below. CORS must run inside the
                // security chain, so browser preflight (OPTIONS) requests aren't
                // rejected as unauthenticated.
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers(PUBLIC, WEBHOOKS)
                        .permitAll()
                        .requestMatchers(EndpointRequest.toAnyEndpoint())
                        .permitAll()
                        .requestMatchers(API_DOCS)
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .sessionManagement(management -> management
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(handling -> handling.authenticationEntryPoint(authEntryPoint));
        // Signing in with Google: under /api/v1/auth, so public like the other logins.
        GoogleSignIn google = googleSignIn.getIfAvailable();
        if (google != null)
            google.configure(http);

        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(authConfigProperties.getCors().getAllowedOrigins());
        config.setAllowedMethods(authConfigProperties.getCors().getAllowedMethods());
        config.setAllowedHeaders(authConfigProperties.getCors().getAllowedHeaders());
        // Scripts can't read it otherwise.
        config.setExposedHeaders(List.of(HttpHeaders.RETRY_AFTER));
        // Lets the frontend send and receive the refresh-token cookie
        // (fetch with credentials: "include"). Requires exact origins, never "*".
        config.setAllowCredentials(true);
        // Browsers may cache a preflight answer for an hour.
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }
}
