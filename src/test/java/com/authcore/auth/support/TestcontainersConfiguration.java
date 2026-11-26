package com.authcore.auth.support;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import java.util.Random;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Real MySQL and Redis for the integration tests, started once and shared by every
 * test class that uses the same Spring context. The images match docker-compose.yml.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfiguration {
    private static final Random RANDOM = new Random();

    /**
     * Every request comes from a different address, unless the test sets one: otherwise all
     * tests together would share the limits of 127.0.0.1.
     */
    @Bean
    MockMvcBuilderCustomizer randomAddresses() {
        return builder -> builder.defaultRequest(get("/").with(request -> {
            request.setRemoteAddr("10." + RANDOM.nextInt(256) + "." + RANDOM.nextInt(256) + "." + RANDOM.nextInt(256));
            return request;
        }));
    }

    @Bean
    @ServiceConnection
    MySQLContainer mysqlContainer() {
        return new MySQLContainer(DockerImageName.parse("mysql:8.4"));
    }

    @Bean
    @ServiceConnection(name = "redis")
    GenericContainer<?> redisContainer() {
        return new GenericContainer<>(DockerImageName.parse("redis:7.4-alpine")).withExposedPorts(6379);
    }
}
