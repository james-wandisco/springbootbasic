package com.example.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.*;
import java.security.cert.CertificateException;

@Controller
public class SimpleController {

    @GetMapping("/client_specification")
    public String client_specificationForm(Model model) {
        model.addAttribute("sslsession", new SSLsession());
        return "client_specification";
    }

    @PostMapping("/client_specification")
    public String greetingSubmit(@ModelAttribute SSLsession sslsession, Model model) {
        model.addAttribute("sslsession", sslsession);
        return "result";
    }

    @Value("${spring.application.name}")
    String appName;
    @Value("${server.ssl.key-store}")
    String keyStorePath;

    @GetMapping("/hello")
    public String homePage(Model model) {
        model.addAttribute("appName", appName);
        return "home";
    }
    @GetMapping("/page2")
    public String page2(Model model) throws IOException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, KeyStoreException, KeyManagementException {
        //model.addAttribute("appName", appName);
       // String host = InformationCreator.getHost();
        //String host = InformationCreator.host();
        //model.addAttribute("host", host);

        String keystore = InformationCreator.showKeystore(keyStorePath);
        model.addAttribute("keystore", keystore);

        Principal principal = InformationCreator.getPrinc();
        model.addAttribute("principal", principal);

        String host = InformationCreator.getHost();
        model.addAttribute("host", host);

        String protocol = InformationCreator.getProtocol();
        model.addAttribute("protocol", protocol);

        Certificate[] certs = InformationCreator.getCerts();
        String c1 = certs[0].toString();
        model.addAttribute("c1", c1);


        return "ssl_information";
    }


    @GetMapping("/page3")
    public String page3(Model model) {
        return "page3";
    }


}
