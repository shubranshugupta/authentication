package com.authcore.auth.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/** The email thread pool (M7, with A3). */
class EmailExecutorTests {
    private final ThreadPoolTaskExecutor executor = new ApplicationConfig(null).emailExecutor();

    @Test
    void shutdownSendsTheQueuedEmailsFirst() {
        executor.initialize();
        AtomicInteger sent = new AtomicInteger();
        for (int i = 0; i < 20; i++)
            executor.execute(() -> {
                try {
                    Thread.sleep(50);
                    sent.incrementAndGet();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });

        executor.shutdown();

        assertThat(sent).hasValue(20);
    }

    /** With the default policy, the request that wanted the email would fail with 500. */
    @Test
    void aFullQueueDropsTheEmailInsteadOfFailingTheRequest() {
        executor.initialize();
        CountDownLatch mailServerIsBack = new CountDownLatch(1);
        Runnable stuckEmail = () -> {
            try {
                mailServerIsBack.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };
        try {
            for (int i = 0; i < ApplicationConfig.EMAIL_QUEUE_CAPACITY + 2; i++)
                executor.execute(stuckEmail);
            AtomicInteger extra = new AtomicInteger();

            assertThatCode(() -> executor.execute(extra::incrementAndGet)).doesNotThrowAnyException();

            assertThat(executor.getThreadPoolExecutor().getQueue()).hasSize(ApplicationConfig.EMAIL_QUEUE_CAPACITY);
            assertThat(extra).hasValue(0);
        } finally {
            mailServerIsBack.countDown();
            executor.shutdown();
        }
    }
}
