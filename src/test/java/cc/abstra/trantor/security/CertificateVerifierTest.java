package cc.abstra.trantor.security;

import cc.abstra.trantor.security.certificate.CertificateVerifier;
import cc.abstra.trantor.security.certificate.crl.CRLVerifier;
import cc.abstra.trantor.security.certificate.crl.exceptions.CRLAccessLocationException;
import cc.abstra.trantor.security.certificate.exceptions.CertificateVerificationException;
import cc.abstra.trantor.security.certificate.exceptions.UnknownTrustException;
import cc.abstra.trantor.security.certificate.ocsp.OCSPVerifier;
import cc.abstra.trantor.security.certificate.ocsp.exceptions.OCSPAccessLocationException;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.*;
import java.util.HashSet;
import java.util.Set;

import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.mockito.Matchers.any;
import static org.powermock.api.mockito.PowerMockito.*;


@PrepareForTest({CertificateVerifier.class, OCSPVerifier.class, CRLVerifier.class})
@PowerMockIgnore("javax.security.*")
@RunWith(PowerMockRunner.class)
public class CertificateVerifierTest {

    Set<X509Certificate> trustedCertificates = new HashSet<>();
    Set<X509Certificate> systemCertificates = new HashSet<>();
    Certificate testCertificate;
    Certificate selfSignedCertificate;

    @Before
    public void setUp() throws Exception {

        TestHelpers helpers = new TestHelpers(this.getClass());

        KeyStore trustedKeyStore = helpers.readCertStoreResource("test_cacerts", "JKS", "changeit");
        // This class retrieves the most-trusted CAs from the keystore
        PKIXParameters params = new PKIXParameters(trustedKeyStore);

        // Get the set of trust anchors, which contain the most-trusted CA certificates
        for (TrustAnchor ta : params.getTrustAnchors()) {
            // Get certificate
            X509Certificate cert = ta.getTrustedCert();
            trustedCertificates.add(cert);
        }

        KeyStore systemKeyStore = helpers.readCertStoreResource("default_cacerts", "JKS", "changeit");
        PKIXParameters params2 = new PKIXParameters(systemKeyStore);
        for (TrustAnchor ta : params2.getTrustAnchors()) {
            X509Certificate cert = ta.getTrustedCert();
            systemCertificates.add(cert);
        }

        KeyStore validKeyStore = helpers.readCertStoreResource("test.p12", "PKCS12", "secret");
        String alias1 = validKeyStore.aliases().nextElement();
        testCertificate = validKeyStore.getCertificate(alias1);

        KeyStore selfSignedKeyStore = helpers.readCertStoreResource("selfsigned.p12", "PKCS12", "secret");
        String alias2 = selfSignedKeyStore.aliases().nextElement();
        selfSignedCertificate = selfSignedKeyStore.getCertificate(alias2);
    }

    @Test
    public void testVerifyCertificateWithValidCertAndCRLValidation() throws CertificateVerificationException,
            OCSPAccessLocationException, CRLAccessLocationException, UnknownTrustException {
        //Mocks
        mockStatic(OCSPVerifier.class);
        doThrow(new OCSPAccessLocationException()).when(OCSPVerifier.class);
        OCSPVerifier.verifyCertificate(any(PKIXCertPathBuilderResult.class));
        mockStatic(CRLVerifier.class);
        doNothing().when(CRLVerifier.class);
        CRLVerifier.verifyCertificate(any(X509Certificate.class));

        PKIXCertPathBuilderResult cp = CertificateVerifier.
                verifyCertificate((X509Certificate) testCertificate, trustedCertificates);
        assertNotNull(cp.getCertPath());
        assertNotNull(cp.getTrustAnchor());
    }

    @Test
    public void testVerifyCertificateWithValidCertAndOCSPValidation() throws CertificateVerificationException,
            OCSPAccessLocationException, UnknownTrustException {
        //Mocks
        mockStatic(OCSPVerifier.class);
        doNothing().when(OCSPVerifier.class);
        OCSPVerifier.verifyCertificate(any(PKIXCertPathBuilderResult.class));

        PKIXCertPathBuilderResult cp = CertificateVerifier.
                verifyCertificate((X509Certificate) testCertificate, trustedCertificates);
        assertNotNull(cp.getCertPath());
        assertNotNull(cp.getTrustAnchor());
    }

    @Test(expected = UnknownTrustException.class)
    public void testVerifyCertificateWithNoCertAndNoOCSPInfo() throws OCSPAccessLocationException,
            CertificateVerificationException, CRLAccessLocationException, UnknownTrustException {
        //Mocks
        mockStatic(OCSPVerifier.class);
        doThrow(new OCSPAccessLocationException()).when(OCSPVerifier.class);
        OCSPVerifier.verifyCertificate(any(PKIXCertPathBuilderResult.class));

        mockStatic(CRLVerifier.class);
        doThrow(new CRLAccessLocationException()).when(CRLVerifier.class);
        CRLVerifier.verifyCertificate(any(X509Certificate.class));

        CertificateVerifier.
                verifyCertificate((X509Certificate) testCertificate, trustedCertificates);
    }


    @Test(expected = CertificateVerificationException.class)
    public void testVerifyCertificateWithNullCert() throws CertificateVerificationException, UnknownTrustException {
        CertificateVerifier.verifyCertificate(null, trustedCertificates);
    }

    @Test(expected = CertificateVerificationException.class)
    public void testVerifyCertificateWithSelfSignedCert() throws CertificateVerificationException, UnknownTrustException {
        CertificateVerifier.verifyCertificate((X509Certificate) selfSignedCertificate, trustedCertificates);
    }

    @Test(expected = CertificateVerificationException.class)
    public void testVerifyCertificateWithCertIssuedByUnknownCA() throws CertificateVerificationException, UnknownTrustException {
        CertificateVerifier.verifyCertificate((X509Certificate) testCertificate, systemCertificates);
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

    @Test(expected = CertificateVerificationException.class)
    public void testVerifyExpiredCertificate() throws Exception {
        //Mocks
        stub(method(CertificateVerifier.class, "hasExpired")).toReturn(true);

        CertificateVerifier.verifyCertificate((X509Certificate) testCertificate, trustedCertificates);
    }

    @Ignore("Pending: not implemented yet")
    @Test
    public void testVerifyCertificateWithCACrossSigning() throws Exception {
    }
}
