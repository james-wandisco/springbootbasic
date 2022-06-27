package com.example.demo;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.Certificate;

public class InformationCreator {

    public static SSLSession startSession() throws IOException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, CertificateException, KeyManagementException {
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
        SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket("151.101.192.81", 443);
        sslSocket.startHandshake();
        SSLSession sslSession = (SSLSession) sslSocket.getSession();
        return sslSession;
    }
    public static String showKeystore(String fullPath) {
        int pos = fullPath.lastIndexOf("/");
        if (pos > -1)
            return fullPath.substring(pos + 1);
        else
            return fullPath;
    }
    public static Principal getPrinc() throws UnrecoverableKeyException, CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        SSLSession session = InformationCreator.startSession();
        return session.getLocalPrincipal();
    }

    public static String getHost() throws UnrecoverableKeyException, CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        SSLSession session = InformationCreator.startSession();
        return session.getPeerHost();
    }

    public static Certificate[] getCerts() throws UnrecoverableKeyException, CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        SSLSession session = InformationCreator.startSession();
        return (Certificate[]) session.getPeerCertificates();
    }

    public static String getProtocol() throws UnrecoverableKeyException, CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        SSLSession session = InformationCreator.startSession();
        return session.getProtocol();
    }

}

