package com.authcore.auth.service;

import java.io.Serializable;
import java.time.Duration;

import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;

import tools.jackson.databind.json.JsonMapper;

@Service
public class CacheService<K extends Serializable, V extends Serializable> {
    private final RedisTemplate<K, V> redisTemplate;
    private final ValueOperations<K, V> valueOperations;
    private final JsonMapper jsonMapper;

    // Named explicitly: Boot's StringRedisTemplate also matches RedisTemplate<K, V>
    // and would otherwise be injected, which breaks for any non-String value.
    public CacheService(@Qualifier("redisTemplate") RedisTemplate<K, V> redisTemplate, JsonMapper jsonMapper) {
        this.redisTemplate = redisTemplate;
        this.valueOperations = redisTemplate.opsForValue();
        this.jsonMapper = jsonMapper;
    }

    public void save(K key, V value, Long expireTime) {
        if (expireTime == null)
            valueOperations.set(key, value);
        else
            valueOperations.set(key, value, Duration.ofMillis(expireTime));
    }

    // The serializer stores plain JSON without type information, so a read returns
    // a Map; convert it into the requested type.
    public @Nullable V getValue(K key, Class<V> type) {
        Object value = valueOperations.get(key);
        return value == null ? null : jsonMapper.convertValue(value, type);
    }

    public void delete(K key) {
        redisTemplate.delete(key);
    }

    public boolean contains(K key) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }
}
