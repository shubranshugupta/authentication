package com.authcore.auth.ratelimit;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

import com.authcore.auth.ratelimit.RateLimit.Counter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Counts requests in Redis (A7), so that the limits hold across several instances of this
 * application. A counter starts with its first request, and is forgotten when its time is up.
 *
 * <p>While Redis is down nothing is limited: an outage must not keep everybody from logging
 * in. Codes still allow only 5 guesses, which are counted in the database.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RateLimiter {
    /** How long Redis isn't asked after it failed. Otherwise every request would wait for its timeout. */
    static final Duration PAUSE = Duration.ofSeconds(5);

    /**
     * In one script, so that requests sent all at once can't get past a limit. If one counter
     * is full, none is raised: what is refused anyway must not use up the other limits.
     * Returns 0, or how many milliseconds until every full counter is forgotten.
     */
    private static final RedisScript<Long> ACQUIRE = RedisScript.of("""
            local wait = 0
            for i, key in ipairs(KEYS) do
                if tonumber(redis.call('GET', key) or '0') >= tonumber(ARGV[2 * i - 1]) then
                    wait = math.max(wait, redis.call('PTTL', key), 1)
                end
            end
            if wait > 0 then
                return wait
            end
            for i, key in ipairs(KEYS) do
                if redis.call('INCR', key) == 1 then
                    redis.call('PEXPIRE', key, ARGV[2 * i])
                end
            end
            return 0
            """, Long.class);

    private static final RedisScript<Long> RELEASE = RedisScript.of("""
            for i, key in ipairs(KEYS) do
                if tonumber(redis.call('GET', key) or '0') > 0 then
                    redis.call('DECR', key)
                end
            end
            return 0
            """, Long.class);

    private final StringRedisTemplate redis;

    private volatile @Nullable Instant pausedUntil;

    /**
     * Counts a request.
     *
     * @throws TooManyRequestsException if one of the limits is reached; nothing is counted then
     */
    public void acquire(Counter... counters) {
        List<String> limits = new ArrayList<>();
        for (Counter counter : counters) {
            limits.add(String.valueOf(counter.limit().max));
            limits.add(String.valueOf(counter.limit().window.toMillis()));
        }
        long wait = ask(() -> redis.execute(ACQUIRE, keys(counters), limits.toArray())).orElse(0L);
        if (wait > 0)
            throw new TooManyRequestsException(Duration.ofMillis(wait));
    }

    /** Takes back what {@link #acquire} counted. */
    public void release(Counter... counters) {
        ask(() -> redis.execute(RELEASE, keys(counters)));
    }

    /** Starts over. */
    public void reset(Counter... counters) {
        ask(() -> redis.delete(keys(counters)));
    }

    private static List<String> keys(Counter... counters) {
        return Arrays.stream(counters).map(Counter::key).toList();
    }

    private <T> Optional<T> ask(Supplier<T> question) {
        Instant until = pausedUntil;
        if (until != null && Instant.now().isBefore(until))
            return Optional.empty();
        try {
            return Optional.ofNullable(question.get());
        } catch (DataAccessException e) {
            pausedUntil = Instant.now().plus(PAUSE);
            log.error("Redis failed: no rate limits for the next {} seconds", PAUSE.toSeconds(), e);
            return Optional.empty();
        }
    }
}
