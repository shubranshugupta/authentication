package com.authcore.auth.ratelimit;

import org.springframework.stereotype.Component;

import com.authcore.auth.ratelimit.RateLimit.Counter;

import lombok.RequiredArgsConstructor;

/**
 * Limits how many passwords can be guessed (H9). A login is counted before its password is
 * checked, and taken back if it was right: if it was counted afterwards, guesses sent all at
 * once would get through.
 */
@Component
@RequiredArgsConstructor
public class LoginThrottle {
    private final RateLimiter rateLimiter;

    /** @throws TooManyRequestsException if there were too many wrong passwords */
    public void beforeCheck(String email, String ip) {
        rateLimiter.acquire(ipAndAccount(email, ip), account(email), RateLimit.LOGIN_PER_IP.forIp(ip));
    }

    public void succeeded(String email, String ip) {
        rateLimiter.release(account(email), RateLimit.LOGIN_PER_IP.forIp(ip));
        rateLimiter.reset(ipAndAccount(email, ip));
    }

    /** The login failed, but not because of a wrong password. */
    public void notAGuess(String email, String ip) {
        rateLimiter.release(ipAndAccount(email, ip), account(email), RateLimit.LOGIN_PER_IP.forIp(ip));
    }

    /** Guesses at the old password don't matter any more, and the owner wants to log in now. */
    public void passwordChanged(String email, String ip) {
        rateLimiter.reset(ipAndAccount(email, ip), account(email));
    }

    private static Counter ipAndAccount(String email, String ip) {
        return RateLimit.LOGIN_PER_IP_AND_ACCOUNT.forIpAndAccount(ip, email);
    }

    private static Counter account(String email) {
        return RateLimit.LOGIN_PER_ACCOUNT.forAccount(email);
    }
}
