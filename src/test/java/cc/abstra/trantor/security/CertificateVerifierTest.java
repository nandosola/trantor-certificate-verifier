package cc.abstra.trantor.security;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;


public class CertificateVerifierTest {

    String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
    String password = "changeit";
    Set<X509Certificate> additionalCerts = new HashSet<X509Certificate>();

    @Before
    public void setUp() throws Exception {

        FileInputStream is = new FileInputStream(filename);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, password.toCharArray());

        // This class retrieves the most-trusted CAs from the keystore
        PKIXParameters params = new PKIXParameters(keystore);

        // Get the set of trust anchors, which contain the most-trusted CA certificates
        for (TrustAnchor ta : params.getTrustAnchors()) {
            // Get certificate
            X509Certificate cert = ta.getTrustedCert();
            additionalCerts.add(cert);
        }
    }

    @After
    public void tearDown() throws Exception {

    }

    @Test
    public void testVerifyCertificate() throws Exception {

    }

    @Test
    public void testIsSelfSigned() throws Exception {

    }
}
