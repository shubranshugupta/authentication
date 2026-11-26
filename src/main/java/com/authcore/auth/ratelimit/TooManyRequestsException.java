package com.authcore.auth.ratelimit;

import java.time.Duration;

import lombok.Getter;

@Getter
public class TooManyRequestsException extends RuntimeException {
    private final long retryAfterSeconds;

    public TooManyRequestsException(Duration retryAfter) {
        super("Too many requests. Try again later.");
        this.retryAfterSeconds = Math.max(1, retryAfter.plusMillis(999).toSeconds()); // rounded up
    }
}
