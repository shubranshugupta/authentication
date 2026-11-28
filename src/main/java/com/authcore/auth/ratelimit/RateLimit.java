package com.authcore.auth.ratelimit;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;

import com.authcore.auth.common.EmailAddresses;

/**
 * How often something may be done. "Account" means the email in the request, whether or not
 * it's registered: otherwise the limits would show which emails are (H2).
 */
public enum RateLimit {
    // Wrong passwords only (H9). Five per account from one address, and not five per account:
    // anyone could lock anyone out with five wrong passwords. The limit for the whole account
    // is there for guesses from many addresses.
    LOGIN_PER_IP_AND_ACCOUNT(5, Duration.ofMinutes(15)),
    LOGIN_PER_ACCOUNT(50, Duration.ofHours(1)),
    LOGIN_PER_IP(50, Duration.ofMinutes(15)),

    REGISTRATION_PER_IP(20, Duration.ofHours(1)),

    // Requests that send an email (H3).
    VERIFICATION_EMAIL_PER_IP(20, Duration.ofHours(1)),
    VERIFICATION_EMAIL_PER_ACCOUNT(10, Duration.ofHours(1)),
    RESET_EMAIL_PER_IP(20, Duration.ofHours(1)),
    RESET_EMAIL_PER_ACCOUNT(10, Duration.ofHours(1)),
    DELETION_EMAIL_PER_USER(10, Duration.ofHours(1)),
    // Codes to an address the user chooses: limited, so that it can't be used to send mail to anybody.
    EMAIL_CHANGE_EMAIL_PER_USER(10, Duration.ofHours(1)),

    // Guesses at codes and links, on top of the 5 per code (C1). The one per account keeps a
    // single address from using up every code of somebody else.
    VERIFICATION_CONFIRM_PER_IP(30, Duration.ofMinutes(15)),
    RESET_CONFIRM_PER_IP(30, Duration.ofMinutes(15)),
    RESET_CONFIRM_PER_IP_AND_ACCOUNT(10, Duration.ofHours(1)),
    EMAIL_CHANGE_UNDO_PER_IP(30, Duration.ofMinutes(15)),
    // Codes from authenticator apps at login. Each account also allows only 5 wrong ones in a
    // row, counted in the database (TwoFactorService).
    SECOND_FACTOR_PER_IP(30, Duration.ofMinutes(15));

    private static final int IPV6_NETWORK_BYTES = 8;

    final int max;
    final Duration window;

    RateLimit(int max, Duration window) {
        this.max = max;
        this.window = window;
    }

    /** What one caller has used up of a limit. */
    public record Counter(RateLimit limit, String subject) {
        String key() {
            return "rate-limit:" + limit + ":" + subject;
        }
    }

    public Counter forIp(String ip) {
        return new Counter(this, network(ip));
    }

    public Counter forAccount(String email) {
        return new Counter(this, hash(email));
    }

    public Counter forIpAndAccount(String ip, String email) {
        return new Counter(this, network(ip) + ":" + hash(email));
    }

    public Counter forUser(Integer userId) {
        return new Counter(this, userId.toString());
    }

    /** An IPv6 customer gets at least a /64 network, so each has billions of addresses. */
    static String network(String ip) {
        if (!ip.contains(":"))
            return ip;
        try {
            // A literal address, so this doesn't look anything up. Without the zone ("%eth0").
            InetAddress address = InetAddress.getByName(ip.split("%")[0]);
            if (!(address instanceof Inet6Address))
                return address.getHostAddress(); // IPv4, written as ::ffff:1.2.3.4
            return HexFormat.of().formatHex(Arrays.copyOf(address.getAddress(), IPV6_NETWORK_BYTES)) + "/64";
        } catch (UnknownHostException e) {
            return ip;
        }
    }

    /** Redis holds no email addresses. */
    private static String hash(String email) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(EmailAddresses.normalize(email).getBytes(UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e); // every Java has SHA-256
        }
    }
}
