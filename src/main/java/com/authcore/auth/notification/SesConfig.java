package com.authcore.auth.notification;

import java.net.URI;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.util.StringUtils;

import com.authcore.auth.common.AuthConfigProperties;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.SesV2ClientBuilder;

/**
 * With MAIL_TRANSPORT=ses, emails go through the SES v2 API. The JavaMailSender here takes
 * the place of Spring Boot's SMTP one, which then isn't made. The credentials are the
 * environment's: an IAM role on AWS, or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "auth.mail.transport", havingValue = "ses")
class SesConfig {
    @Bean
    SesV2Client sesClient(AuthConfigProperties properties) {
        AuthConfigProperties.SesConfigProperties ses = properties.getMail().getSes();
        SesV2ClientBuilder builder = SesV2Client.builder()
                .region(Region.of(ses.getRegion()))
                .credentialsProvider(DefaultCredentialsProvider.builder().build())
                .httpClientBuilder(UrlConnectionHttpClient.builder());
        if (StringUtils.hasText(ses.getEndpoint()))
            builder.endpointOverride(URI.create(ses.getEndpoint()));
        return builder.build();
    }

    @Bean
    JavaMailSender mailSender(SesV2Client ses, AuthConfigProperties properties) {
        return new SesMailSender(ses, properties.getMail().getSes().getConfigurationSet());
    }
}
