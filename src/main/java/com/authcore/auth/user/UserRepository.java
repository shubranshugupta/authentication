package com.authcore.auth.user;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

import jakarta.persistence.LockModeType;

public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByEmail(String email);

    /** Other transactions that lock or change this user wait until this one ends. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.id = :id")
    Optional<User> findAndLockById(Integer id);

    /** Locks several users, in id order like everywhere else, so that two of these can't deadlock. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.id in :ids order by u.id")
    List<User> lockAll(Collection<Integer> ids);

    /** Whether any password hash is from before Argon2id (PasswordHashing). */
    @Query("select count(u) > 0 from User u where u.password not like '{argon2}%'")
    boolean anyOldPasswordHashes();
}
