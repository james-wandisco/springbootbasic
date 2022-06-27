package com.example.demo;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class SSLsession {

    private String ip;

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public static SSLSession startSession(String ip) throws IOException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, CertificateException, KeyManagementException {
        // Keystore specify, just use any
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("/Users/James/Downloads/Lab_Stuff/springbootbasic/src/main/resources/certs/truststore.jks"), "wandisco".toCharArray());
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(keyStore, "wandisco".toCharArray());
        KeyManager[] km = keyManagerFactory.getKeyManagers();
        // Truststore, specify correctly pre application test
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream("/Program Files/Java/jdk1.8.0_191/jre/lib/security/cacerts"), "changeit".toCharArray());
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
        trustManagerFactory.init(trustStore);
        TrustManager[] tm = trustManagerFactory.getTrustManagers();
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(km, tm, null);

        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(ip, 443);
        sslSocket.startHandshake();
        SSLSession sslSession = (SSLSession) sslSocket.getSession();
        return sslSession;
    }
    public static String getHost(String ip) throws UnrecoverableKeyException, CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        SSLSession session = startSession(ip);
        return session.getPeerHost();
    }
}
