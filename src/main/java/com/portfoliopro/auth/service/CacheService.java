package com.portfoliopro.auth.service;

import java.io.Serializable;
import java.util.LinkedHashMap;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

@Service
public class CacheService<K extends Serializable, V extends Serializable> {
    private final RedisTemplate<K, V> redisTemplate;
    private final ValueOperations<K, V> valueOperations;
    private final ObjectMapper objectMapper;

    public CacheService(RedisTemplate<K, V> redisTemplate, ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.valueOperations = redisTemplate.opsForValue();
        this.objectMapper = objectMapper;
    }

    public void save(K key, V value) {
        valueOperations.set(key, value);
    }

    @SuppressWarnings("unchecked")
    public V getValue(K key, @NonNull Class<V> type) {
        LinkedHashMap<String, Object> map = (LinkedHashMap<String, Object>) valueOperations.get(key);
        return objectMapper.convertValue(map, type);
    }

    public void delete(K key) {
        redisTemplate.delete(key);
    }

    public boolean contains(K key) {
        return redisTemplate.hasKey(key);
    }
}
