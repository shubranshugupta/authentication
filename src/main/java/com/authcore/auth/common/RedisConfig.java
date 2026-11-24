package com.authcore.auth.common;

import java.io.Serializable;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJacksonJsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;

import tools.jackson.databind.json.JsonMapper;

/**
 * Redis connection settings come from Spring Boot's {@code spring.data.redis.*}
 * properties. This class only defines the template {@code CacheService} uses:
 * string keys, and values stored as JSON written by Boot's {@link JsonMapper}.
 *
 * <p>The bean is named {@code redisTemplate}, so it replaces Boot's default
 * template. {@code CacheService} asks for it by that name, because Boot's
 * {@code StringRedisTemplate} also matches its generic type.
 */
@Configuration
public class RedisConfig {

    @Bean
    RedisTemplate<String, Serializable> redisTemplate(RedisConnectionFactory connectionFactory,
            JsonMapper jsonMapper) {
        RedisTemplate<String, Serializable> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        template.setKeySerializer(RedisSerializer.string());
        template.setValueSerializer(new GenericJacksonJsonRedisSerializer(jsonMapper));

        return template;
    }
}
