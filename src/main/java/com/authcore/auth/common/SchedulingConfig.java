package com.authcore.auth.common;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Runs the @Scheduled cleanup jobs. Every server runs them; that's safe, because they
 * lock what they delete.
 */
@Configuration
@EnableScheduling
public class SchedulingConfig {
}
