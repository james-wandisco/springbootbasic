package com.example.demo;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class contextSSL {

    public static SSLContext createSslContext(String truststorePath,
                                          String truststorePassword,
                                          String keystorePath,
                                          String keystorePassword,
                                          String storeType) throws IOException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, CertificateException, KeyManagementException {
        // Keystore specify, just use any
        KeyStore keyStore = KeyStore.getInstance(storeType);
        keyStore.load(new FileInputStream(keystorePath), keystorePassword.toCharArray());
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(keyStore, keystorePassword.toCharArray());
        KeyManager[] km = keyManagerFactory.getKeyManagers();

        // Truststore, specify correctly pre application test
        KeyStore trustStore = KeyStore.getInstance(storeType);
        trustStore.load(new FileInputStream(truststorePath), truststorePassword.toCharArray());
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
        trustManagerFactory.init(trustStore);
        TrustManager[] tm = trustManagerFactory.getTrustManagers();

        // SSL context creation.
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(km, tm, null);

        return sslContext;
    }
}
