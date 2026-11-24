package com.authcore.auth.notification;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
@EnableAsync
public class EmailConfig {
    static final String EMAIL_EXECUTOR = "emailExecutor";
    static final int EMAIL_QUEUE_CAPACITY = 500;

    /** Sends the emails. Its threads are named email-1 and email-2. */
    @Bean(EMAIL_EXECUTOR)
    ThreadPoolTaskExecutor emailExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(2);
        executor.setQueueCapacity(EMAIL_QUEUE_CAPACITY);
        executor.setThreadNamePrefix("email-");
        // On shutdown, first send what is already queued.
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);
        // When the queue is full, drop the email. The default throws in the middle of the
        // request, and only requests that really send an email would fail: that shows
        // which accounts exist (H2).
        executor.setRejectedExecutionHandler((task, pool) -> log.error("The email queue is full; an email was dropped"));
        return executor;
    }
}
