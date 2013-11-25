package cc.abstra.trantor.security;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.*;
import java.util.HashSet;
import java.util.Set;

import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertFalse;


public class CertificateVerifierTest {

    Set<X509Certificate> trustedCertificates = new HashSet<>();
    Set<X509Certificate> systemCertificates = new HashSet<>();
    Certificate testCertificate;
    Certificate selfSignedCertificate;

    @Before
    public void setUp() throws Exception {

        KeyStore trustedKeyStore = readCertStoreResource("test_cacerts", "JKS", "changeit");
        // This class retrieves the most-trusted CAs from the keystore
        PKIXParameters params = new PKIXParameters(trustedKeyStore);

        // Get the set of trust anchors, which contain the most-trusted CA certificates
        for (TrustAnchor ta : params.getTrustAnchors()) {
            // Get certificate
            X509Certificate cert = ta.getTrustedCert();
            trustedCertificates.add(cert);
        }

        KeyStore systemKeyStore = readCertStoreResource("default_cacerts", "JKS", "changeit");
        PKIXParameters params2 = new PKIXParameters(systemKeyStore);
        for (TrustAnchor ta : params2.getTrustAnchors()) {
            X509Certificate cert = ta.getTrustedCert();
            systemCertificates.add(cert);
        }

        KeyStore validKeyStore = readCertStoreResource("test.p12", "PKCS12", "secret");
        String alias1 = validKeyStore.aliases().nextElement();
        testCertificate = validKeyStore.getCertificate(alias1);

        KeyStore selfSignedKeyStore = readCertStoreResource("selfsigned.p12", "PKCS12", "secret");
        String alias2 = selfSignedKeyStore.aliases().nextElement();
        selfSignedCertificate = selfSignedKeyStore.getCertificate(alias2);
    }

    @Test
    public void testVerifyCertificateWithValidCert() throws CertificateVerificationException {
        PKIXCertPathBuilderResult cp = CertificateVerifier.
                verifyCertificate((X509Certificate) testCertificate, trustedCertificates);
        assertNotNull(cp.getCertPath());
        assertNotNull(cp.getTrustAnchor());
    }

    @Test(expected = CertificateVerificationException.class)
    public void testVerifyCertificateWithSelfSignedCert() throws CertificateVerificationException {
        CertificateVerifier.verifyCertificate((X509Certificate) selfSignedCertificate, trustedCertificates);
    }

    @Test(expected = CertificateVerificationException.class)
    public void testVerifyCertificateWithCertIssuedByUnknownCA() throws CertificateVerificationException {
        CertificateVerifier.verifyCertificate((X509Certificate) testCertificate, systemCertificates);
    }

    @Test
    public void testVerifyCertificateWithExpiredCert() throws CertificateVerificationException {
        CertificateVerifier.verifyCertificate((X509Certificate) testCertificate, trustedCertificates);
    }

    @Test
    public void testIsSelfSigned() throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
        assertTrue(CertificateVerifier.isSelfSigned((X509Certificate) selfSignedCertificate));
        assertFalse(CertificateVerifier.isSelfSigned((X509Certificate) testCertificate));
    }

    @Test
    public void testHasExpired()  {
        assertFalse(CertificateVerifier.hasExpired((X509Certificate) testCertificate));
    }

    @Ignore("Pending: not implemented yet")
    @Test
    public void VerifyCertificateWithCACrossSigning() throws Exception {

    }

    private KeyStore readCertStoreResource(String resourceName, String storeType, String storePassword)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {

        URL certStoreUrl = this.getClass().getResource("/"+resourceName);
        InputStream certStoreIS = certStoreUrl.openStream();
        KeyStore ks = KeyStore.getInstance(storeType);
        ks.load(certStoreIS, storePassword.toCharArray());
        return ks;
    }
}
