package com.example.demo;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.security.cert.X509Certificate;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class StringTester {

    public static void main(String[] args) throws UnrecoverableKeyException, CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, javax.security.cert.CertificateException, SignatureException, InvalidKeyException, NoSuchProviderException {

        String trustStorePath = "/Users/James/Downloads/Lab_Stuff/springbootbasic/src/main/resources/certs/truststore.jks";
        String trustStorePassword = "wandisco";
        String keyStorePath = "/Users/James/Downloads/Lab_Stuff/springbootbasic/src/main/resources/certs/keystore.jks";
        String keyStorePassword = "wandisco";
        String storeType = "JKS";
        String hostname = "localhost";
        int port = 8081;
        SSLContext sslContext = contextSSL.createSslContext(trustStorePath,
                trustStorePassword,
                keyStorePath,
                keyStorePassword,
                storeType);

        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(hostname, port);
        sslSocket.startHandshake();
        SSLSession sessionToServer = (SSLSession) sslSocket.getSession();

        // Get cert array and certchain array
        System.out.println("DEBUG. Pulling back certs from server " + hostname );
        Certificate[] serverCerts = sessionToServer.getPeerCertificates();
        X509Certificate[] serverCertChain = sessionToServer.getPeerCertificateChain();
        int numberOfServerCerts = serverCerts.length;
        int numberOfServerCertsInChain = serverCertChain.length;
        System.out.println("DEBUG. Number of numberOfServerCerts: " + numberOfServerCerts);
        System.out.println("DEBUG. Number of numberOfServerCertsInChain: " + numberOfServerCertsInChain);

        System.out.println("DEBUG. Checking all peer certs for public key...");
        for(int i=0; i< numberOfServerCerts; i++){
            Certificate cert = serverCerts[i];
            String certval1 = cert.getPublicKey().toString();
            System.out.println("DEBUG. Peer Cert number: " + i + " Public key: " + certval1);
        }

        System.out.println("DEBUG. Checking cert chain for SubjectDN...");
        for(int i=0; i< numberOfServerCertsInChain; i++){
            X509Certificate cert = serverCertChain[i];
            String certval1 = cert.getSubjectDN().toString();
            String certval2 = cert.toString();
            System.out.println("DEBUG. Cert number: " + i + " SubjectDN: " + certval1);
            System.out.println("DEBUG. Cert number: " + i + " Whole thing : " + certval2);
        }

        Certificate[] clientCerts = sessionToServer.getLocalCertificates();
        int numberOfClientCerts = clientCerts.length;
        System.out.println("DEBUG. Number of numberOfLocalCerts: " + numberOfClientCerts);

        for(int i=0; i< numberOfClientCerts; i++){
            Certificate clientCert = clientCerts[i];
            String certval3 = clientCert.getPublicKey().toString();
            System.out.println("DEBUG. Local Cert number: " + i + " Public key: " + certval3);
        }


//        String c1 = chain[0].toString();
//        X509Certificate cer1 = chain[0];
//        String cn = cer1.getSubjectDN().toString();
//        String signaturealgoname = cer1.getSigAlgName();
//        String issuer = cer1.getIssuerDN().toString();
//        PublicKey pubk = cer1.getPublicKey();
//
//        try {
//            cer1.verify(pubk);
//        } catch (Exception e){ System.out.println("cert valid");}
//
//        String kepformat = pubk.getFormat();
//
//        System.out.println("cn:" + cn);
//        System.out.println("signaturealgoname:" + signaturealgoname);
//        System.out.println("issuer:" + issuer);
//        System.out.println("public key format:" + kepformat);
//
//        String storeType = "JKS";
//        String truststorePath = "/Users/James/Downloads/Lab_Stuff/springbootbasic/src/main/resources/certs/truststore.jks";
//        String truststorePassword = "wandisco";
//        KeyStore trustStore = KeyStore.getInstance(storeType);
//        trustStore.load(new FileInputStream(truststorePath), truststorePassword.toCharArray());
//
//
//        System.out.println("I am looking up the peerCert in our truststore..");
//        String alias = trustStore.getCertificateAlias(peerCert1);
//        System.out.println("I see alias of:" + alias);


    }

}
////        String cert1 = " [ [ Version: V3 Subject: CN=www.bbc.com, O=BRITISH BROADCASTING CORPORATION, L=London, ST=London, C=GB Signature Algorithm: SHA256withRSA, OID = 1.2.840.113549.1.1.11 Key: Sun RSA public key, 2048 bits modulus: 24435975298239918058320024843190249172168706864347806341348021142500944099231478193650528620824606088436414841745054746449236773280937887281933843954391629986219874457259386326517657849273211525720381297341486210082589393947823552716538934687760094913268011709327542482541848615458243788559935914929667813703904718354747442183413883014255620633876030966849610703980162334077559724002469314738539332560325437360667744898925530402078724525365854537663520670143952017605174033064593695576989505141977743339192974568997010346955278028801903792041768143788983388075650523395814695406117072610127112418158829872052573632657 public exponent: 65537 Validity: [From: Fri Mar 04 13:51:12 GMT 2022, To: Wed Apr 05 14:51:11 BST 2023] Issuer: CN=GlobalSign RSA OV SSL CA 2018, O=GlobalSign nv-sa, C=BE SerialNumber: [ 3e55353c c99bcb59 6ebefc64] Certificate Extensions: 10 [1]: ObjectId: 1.3.6.1.4.1.11129.2.4.2 Criticality=false Extension unknown: DER encoded OCTET string = 0000: 04 82 01 6D 04 82 01 69 01 67 00 76 00 E8 3E D0 ...m...i.g.v..>. 0010: DA 3E F5 06 35 32 E7 57 28 BC 89 6B C9 03 D3 CB .>..52.W(..k.... 0020: D1 11 6B EC EB 69 E1 77 7D 6D 06 BD 6E 00 00 01 ..k..i.w.m..n... 0030: 7F 55 32 EB 0E 00 00 04 03 00 47 30 45 02 21 00 .U2.......G0E.!. 0040: A0 2C D4 EB F6 65 41 0B 0C 98 1D 77 FC 68 16 1C .,...eA....w.h.. 0050: 97 CD 25 B1 06 E4 CB 1E 69 67 26 A5 25 7A 2F B0 ..%.....ig&.%z/. 0060: 02 20 7A 36 91 D9 78 DF B7 4C 33 A7 A9 F1 88 58 . z6..x..L3....X 0070: 8C 6A 71 94 AB C7 9D C2 AF 98 61 81 CA 8C C3 32 .jq.......a....2 0080: B0 BB 00 76 00 6F 53 76 AC 31 F0 31 19 D8 99 00 ...v.oSv.1.1.... 0090: A4 51 15 FF 77 15 1C 11 D9 02 C1 00 29 06 8D B2 .Q..w.......)... 00A0: 08 9A 37 D9 13 00 00 01 7F 55 32 E8 0C 00 00 04 ..7......U2..... 00B0: 03 00 47 30 45 02 21 00 AE FC D5 FB 98 F6 FC FC ..G0E.!......... 00C0: 9D 93 07 C3 4E FC C0 75 7C EE E0 19 B7 7F 92 D0 ....N..u........ 00D0: 84 AC 3F A8 7C 78 64 BB 02 20 09 73 11 E4 3D 58 ..?..xd.. .s..=X 00E0: DC 4D 93 64 57 E5 70 25 62 43 57 D2 7F 05 46 79 .M.dW.p%bCW...Fy 00F0: 75 29 4A C4 3C 7D AC F8 C2 0C 00 75 00 55 81 D4 u)J.<......u.U.. 0100: C2 16 90 36 01 4A EA 0B 9B 57 3C 53 F0 C0 E4 38 ...6.J...W<S...8 0110: 78 70 25 08 17 2F A3 AA 1D 07 13 D3 0C 00 00 01 xp%../.......... 0120: 7F 55 32 E8 34 00 00 04 03 00 46 30 44 02 20 54 .U2.4.....F0D. T 0130: B9 C4 9B 2E DE 1C D0 CD FB FF AF FB 16 5F 99 61 ............._.a 0140: 77 BF 6D AC B3 E9 59 50 56 01 2D 91 5C 96 9F 02 w.m...YPV.-.\\... 0150: 20 01 6D 0C B2 88 72 0E 7F 44 C9 AE 3E BA 57 1A .m...r..D..>.W. 0160: 7B D4 5F FC ED 0C 6B 3D 0C D0 EA E4 BE 67 88 81 .._...k=.....g.. 0170: 23 # [2]: ObjectId: 1.3.6.1.5.5.7.1.1 Criticality=false AuthorityInfoAccess [ [ accessMethod: caIssuers accessLocation: URIName: http://secure.globalsign.com/cacert/gsrsaovsslca2018.crt , accessMethod: ocsp accessLocation: URIName: http://ocsp.globalsign.com/gsrsaovsslca2018 ] ] [3]: ObjectId: 2.5.29.35 Criticality=false AuthorityKeyIdentifier [ KeyIdentifier [ 0000: F8 EF 7F F2 CD 78 67 A8 DE 6F 8F 24 8D 88 F1 87 .....xg..o.$.... 0010: 03 02 B3 EB .... ] ] [4]: ObjectId: 2.5.29.19 Criticality=false BasicConstraints:[ CA:false PathLen: undefined ] [5]: ObjectId: 2.5.29.31 Criticality=false CRLDistributionPoints [ [DistributionPoint: [URIName: http://crl.globalsign.com/gsrsaovsslca2018.crl] ]] [6]: ObjectId: 2.5.29.32 Criticality=false CertificatePolicies [ [CertificatePolicyId: [1.3.6.1.4.1.4146.1.20] [PolicyQualifierInfo: [ qualifierID: 1.3.6.1.5.5.7.2.1 qualifier: 0000: 16 26 68 74 74 70 73 3A 2F 2F 77 77 77 2E 67 6C .&https://www.gl 0010: 6F 62 61 6C 73 69 67 6E 2E 63 6F 6D 2F 72 65 70 obalsign.com/rep 0020: 6F 73 69 74 6F 72 79 2F ository/ ]] ] [CertificatePolicyId: [2.23.140.1.2.2] [] ] ] [7]: ObjectId: 2.5.29.37 Criticality=false ExtendedKeyUsages [ serverAuth clientAuth ] [8]: ObjectId: 2.5.29.15 Criticality=true KeyUsage [ DigitalSignature Key_Encipherment ] [9]: ObjectId: 2.5.29.17 Criticality=false SubjectAlternativeName [ DNSName: www.bbc.com DNSName: www.bbc.co.uk DNSName: bbc.co.uk DNSName: bbcrussian.com DNSName: *.bbc.com DNSName: *.bbcrussian.com DNSName: bbc.com ] [10]: ObjectId: 2.5.29.14 Criticality=false SubjectKeyIdentifier [ KeyIdentifier [ 0000: 7C 48 B3 B1 0D 48 93 A2 D2 F0 AC F4 F6 13 EF 75 .H...H.........u 0010: 94 CF 80 97 .... ] ] ] Algorithm: [SHA256withRSA] Signature: 0000: 14 40 09 BD 42 2D BC 29 4D DA 58 55 87 05 DC 8B .@..B-.)M.XU.... 0010: 1E 1C E9 1A 77 C4 CB B2 35 FD B1 3B EE 5C 97 EF ....w...5..;.\\.. 0020: C9 B0 BB C4 3A 9C 88 81 FF E9 02 9E 91 9E 0E 85 ....:........... 0030: 5D 32 4E D5 7F 1C CD 7B BC 0B 7B 00 C6 07 3E B2 ]2N...........>. 0040: C0 0A EB 9D F1 A5 28 CF EB 9F 12 D0 DA 75 6E F3 ......(......un. 0050: DA 74 36 E5 6C 8A 75 41 13 4B 2B ED 83 24 D1 D1 .t6.l.uA.K+..$.. 0060: E6 6D 85 60 86 22 B2 C7 FF 61 0D 0D 91 1C B9 FF .m.`.\"...a...... 0070: 18 00 ED 16 09 5D 74 DD CB BD 85 CA 5A 46 38 F6 .....]t.....ZF8. 0080: 86 07 74 21 24 DD BE 5B 6F 43 E8 64 79 70 65 C7 ..t!$..[oC.dype. 0090: 79 0F 44 B2 08 6F A6 1E 73 4E 9A E2 6F 0A 5C AE y.D..o..sN..o.\\. 00A0: 99 BF F9 B3 EF B2 F4 E6 BB 1D 52 92 FD 03 14 00 ..........R..... 00B0: 24 47 0C 00 BB 3B 33 F4 2F D9 1C 00 FC E2 57 8D $G...;3./.....W. 00C0: A4 BF 2F BF 5D 94 C2 AB 48 3E 24 00 39 1F 68 29 ../.]...H>$.9.h) 00D0: F2 E1 BA 24 9F 96 9C 24 D1 82 5D 49 70 9A 5F 56 ...$...$..]Ip._V 00E0: 1A 2D 14 C2 6B 02 AB 9F F1 6B 87 C2 E9 2E 46 C1 .-..k....k....F. 00F0: 7A 08 95 94 7C B4 3A 07 C1 C7 FE 0B DF C3 48 68 z.....:.......Hh ]";
////        System.out.println(cert1);
////        int cnStart = cert1.indexOf("=");
////        System.out.println(cnStart);
////        String cnSub = cert1.substring(cnStart + 1);
////        System.out.println(cnSub);
////        int cnEnd = cnSub.indexOf(",");
////        System.out.println(cnEnd);
////        String cn = cnSub.substring(0, cnEnd);
////        System.out.println(cn);