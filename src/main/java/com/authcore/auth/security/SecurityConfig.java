package com.authcore.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {
    /** Everything else needs a login. */
    static final RequestMatcher PUBLIC = PathPatternRequestMatcher.pathPattern("/api/v1/auth/**");

    private final JwtAuthFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final AuthConfigProperties authConfigProperties;
    private final DelegatedAuthenticationEntryPoint authEntryPoint;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf
                .disable())
                // Uses the corsConfigurationSource bean below. CORS must run inside the
                // security chain, so browser preflight (OPTIONS) requests aren't
                // rejected as unauthenticated.
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers(PUBLIC)
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .sessionManagement(management -> management
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(handling -> handling.authenticationEntryPoint(authEntryPoint));

        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(authConfigProperties.getCors().getAllowedOrigins());
        config.setAllowedMethods(authConfigProperties.getCors().getAllowedMethods());
        config.setAllowedHeaders(authConfigProperties.getCors().getAllowedHeaders());
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
