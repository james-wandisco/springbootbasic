package com.example.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.*;
import java.security.cert.CertificateException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
public class SimpleController {

    @GetMapping("/getservercertinfo")
    public String getservercertinfo(Model model)
            throws UnrecoverableKeyException,
            CertificateException,
            IOException,
            NoSuchAlgorithmException,
            KeyStoreException, KeyManagementException, InterruptedException {

        // ip, truststorePath, keystorePath
        //SSLSession session = connectSSL.startSession("151.101.192.81", "443", "/Program Files/Java/jdk1.8.0_191/jre/lib/security/cacerts", "changeit", "/Users/James/Downloads/Lab_Stuff/springbootbasic/src/main/resources/certs/keystore.jks", "wandisco", "JKS");
        SSLContext sslContext = contextSSL.createSslContext("/Program Files/Java/jdk1.8.0_191/jre/lib/security/cacerts", "changeit", "/Users/James/Downloads/Lab_Stuff/springbootbasic/src/main/resources/certs/keystore.jks", "wandisco", "JKS");
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket("151.101.192.81", 443);
        sslSocket.startHandshake();
        SSLSession session = (SSLSession) sslSocket.getSession();
//        String[] values = session.getValueNames();
//        for(int i=0; i< values.length; i++){
//            log.info("current element is: " + values[i]);
//        }


        String protocol = session.getProtocol();
        model.addAttribute("protocol", protocol);

        Certificate[] cert = session.getPeerCertificates();
        Certificate c1 = cert[0];

        model.addAttribute("cert", c1);




        // web page we return
        return "getservercertinfo";

    }

}
