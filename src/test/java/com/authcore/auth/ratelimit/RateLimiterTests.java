package com.authcore.auth.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.when;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.data.redis.core.StringRedisTemplate;

/** What the integration tests (RateLimitTests) can't show. */
class RateLimiterTests {

    /** One request waits for the timeout, not all of them. */
    @Test
    void afterRedisFailedNothingIsLimitedAndItIsNotAskedForAWhile() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        when(redis.execute(any(), anyList(), any(Object[].class))).thenThrow(new QueryTimeoutException("timeout"));
        RateLimiter limiter = new RateLimiter(redis);

        for (int i = 0; i < 100; i++)
            assertThatCode(() -> limiter.acquire(RateLimit.LOGIN_PER_IP.forIp("203.0.113.7"))).doesNotThrowAnyException();

        assertThat(mockingDetails(redis).getInvocations()).hasSize(1);
    }

    @Test
    void theWaitIsRoundedUpToSeconds() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        when(redis.execute(any(), anyList(), any(Object[].class))).thenReturn(1L);

        assertThatThrownBy(() -> new RateLimiter(redis).acquire(RateLimit.LOGIN_PER_IP.forIp("203.0.113.7")))
                .isInstanceOfSatisfying(TooManyRequestsException.class,
                        e -> assertThat(e.getRetryAfterSeconds()).isEqualTo(1));
        assertThat(new TooManyRequestsException(Duration.ofMillis(1001)).getRetryAfterSeconds()).isEqualTo(2);
        assertThat(new TooManyRequestsException(Duration.ofSeconds(900)).getRetryAfterSeconds()).isEqualTo(900);
    }

    @Test
    void addressesAreGroupedByNetwork() {
        assertThat(RateLimit.network("203.0.113.7")).isEqualTo("203.0.113.7");
        assertThat(RateLimit.network("2001:db8:1:2:3:4:5:6")).isEqualTo("20010db800010002/64")
                .isEqualTo(RateLimit.network("2001:DB8:1:2::9"))
                .isNotEqualTo(RateLimit.network("2001:db8:1:3::9"));
        assertThat(RateLimit.network("fe80::1%eth0")).isEqualTo("fe80000000000000/64");
        assertThat(RateLimit.network("::ffff:203.0.113.7")).isEqualTo("203.0.113.7");
        assertThat(RateLimit.network("0:0:0:0:0:0:0:1")).isEqualTo("0000000000000000/64");
        assertThat(RateLimit.network("not:an:address")).isEqualTo("not:an:address");
    }
}
