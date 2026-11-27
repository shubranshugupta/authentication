package com.authcore.auth.session;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.regex.Pattern;

import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Service;

import com.authcore.auth.common.RetryingTransaction;
import com.authcore.auth.user.User;
import com.authcore.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;

/**
 * Remembers the browsers and apps each user logs in from, so that a login from a new one
 * can be emailed to the owner (F5). A device is a random id the client keeps in a cookie
 * ("deviceId"); only its hash is stored. It's the same id for every account logged in from
 * that browser, but each account remembers it separately.
 *
 * <p>Like everything else that changes a user's rows, it locks the user's row first, so
 * that two logins at once from one new device send one email, not two.
 */
@Service
@RequiredArgsConstructor
public class DeviceService {
    /** A device not seen for this long counts as new again; the cleanup job then deletes it. */
    public static final Duration REMEMBERED_FOR = Duration.ofDays(90);
    /** The first login of an account this young is its owner's, right after signing up. */
    static final Duration NEW_ACCOUNT = Duration.ofDays(1);

    private static final Pattern DEVICE_ID = Pattern.compile("[A-Za-z0-9_-]{43}");

    private final KnownDeviceRepository deviceRepository;
    private final UserRepository userRepository;
    private final RetryingTransaction transaction;

    /**
     * The device a user just logged in from.
     *
     * @param deviceId what the client sent; null, or anything that isn't an id we hand out,
     *                 counts as a device never seen before
     * @return the id the client keeps from now on, and whether the owner should hear of it
     */
    public DeviceCheck remember(Integer userId, @Nullable String deviceId) {
        String id = deviceId != null && DEVICE_ID.matcher(deviceId).matches() ? deviceId : SessionService.randomToken();
        String hash = SessionService.hash(id);
        boolean isNew = transaction.run(() -> userRepository.findAndLockById(userId)
                .map(user -> remember(user, hash, Instant.now()))
                .orElse(false)); // deleted a moment ago
        return new DeviceCheck(id, isNew);
    }

    private boolean remember(User user, String hash, Instant now) {
        Optional<KnownDevice> known = deviceRepository.findByUserIdAndDeviceHash(user.getId(), hash);
        if (known.isPresent()) {
            boolean forgotten = !known.get().getLastSeenAt().isAfter(now.minus(REMEMBERED_FOR));
            known.get().seen(now);
            deviceRepository.save(known.get());
            return forgotten;
        }
        boolean signUp = !deviceRepository.existsByUserId(user.getId())
                && user.getCreatedAt().isAfter(now.minus(NEW_ACCOUNT));
        deviceRepository.save(new KnownDevice(user.getId(), hash, now));
        return !signUp;
    }

    /**
     * @param deviceId the id the client keeps (in the cookie), never stored
     * @param isNew    the owner should be told about this login
     */
    public record DeviceCheck(String deviceId, boolean isNew) {
        /** Leaves the id out: logs must not contain it. */
        @Override
        public String toString() {
            return "DeviceCheck[isNew=" + isNew + "]";
        }
    }
}
