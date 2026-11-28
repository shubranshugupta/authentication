package com.authcore.auth.notification;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

/**
 * The public keys SNS signs its messages with, from the certificate each message names.
 * The caller checks first that the certificate's URL is SNS's; each one is fetched once.
 */
@Component
class SnsCertificates {
    private static final int MAX_CACHED = 100;

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final Map<URI, PublicKey> keys = new ConcurrentHashMap<>();

    /** @throws IllegalStateException if it can't be fetched or isn't a valid certificate now */
    PublicKey publicKey(URI certificateUrl) {
        PublicKey cached = keys.get(certificateUrl);
        if (cached != null)
            return cached;
        PublicKey key = fetch(certificateUrl);
        if (keys.size() < MAX_CACHED)
            keys.put(certificateUrl, key);
        return key;
    }

    private PublicKey fetch(URI certificateUrl) {
        try {
            HttpResponse<byte[]> answer = http.send(HttpRequest.newBuilder(certificateUrl)
                    .timeout(Duration.ofSeconds(10)).GET().build(), HttpResponse.BodyHandlers.ofByteArray());
            if (answer.statusCode() != 200)
                throw new IllegalStateException("The SNS certificate answered " + answer.statusCode());
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(answer.body()));
            certificate.checkValidity();
            return certificate.getPublicKey();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted fetching the SNS certificate", e);
        } catch (Exception e) {
            throw e instanceof IllegalStateException ise ? ise
                    : new IllegalStateException("The SNS certificate could not be read", e);
        }
    }
}
