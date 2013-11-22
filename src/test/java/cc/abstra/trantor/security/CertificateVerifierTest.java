package cc.abstra.trantor.security;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;


public class CertificateVerifierTest {


    Set<X509Certificate> caCertificates = new HashSet<X509Certificate>();
    Certificate certificateToValidate;

    @Before
    public void setUp() throws Exception {

        //TODO read files from test/resources
        // TODO refactor to readInputCert()
        InputStream inStream = new FileInputStream("/var/tmp/certificate.p12");
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(inStream, "secret".toCharArray());
        String alias = ks.aliases().nextElement();
        certificateToValidate = ks.getCertificate(alias);

        //TODO refactor to readCACerts()
        String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
        String password = "changeit";
        FileInputStream is = new FileInputStream(filename);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, password.toCharArray());

        // This class retrieves the most-trusted CAs from the keystore
        PKIXParameters params = new PKIXParameters(keystore);

        // Get the set of trust anchors, which contain the most-trusted CA certificates
        for (TrustAnchor ta : params.getTrustAnchors()) {
            // Get certificate
            X509Certificate cert = ta.getTrustedCert();
            caCertificates.add(cert);
        }
    }

    @After
    public void tearDown() throws Exception {
        CertificateVerifier.verifyCertificate((X509Certificate) certificateToValidate, caCertificates);
    }

    @Test
    public void testVerifyCertificate() throws Exception {

    }

    @Test
    public void testIsSelfSigned() throws Exception {

    }
}
