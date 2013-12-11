package cc.abstra.trantor.security;

import cc.abstra.trantor.security.certificate.CertificateVerifier;
import cc.abstra.trantor.security.certificate.ICertStatus;
import cc.abstra.trantor.security.certificate.crl.CRLVerifier;
import cc.abstra.trantor.security.certificate.crl.exceptions.CRLAccessLocationException;
import cc.abstra.trantor.security.certificate.crl.exceptions.CRLClientException;
import cc.abstra.trantor.security.certificate.exceptions.CertificateVerificationException;
import cc.abstra.trantor.security.certificate.exceptions.UnknownTrustException;
import cc.abstra.trantor.security.certificate.ocsp.OCSPClient;
import cc.abstra.trantor.security.certificate.ocsp.OCSPResponse;
import cc.abstra.trantor.security.certificate.ocsp.OCSPStatus;
import cc.abstra.trantor.security.certificate.ocsp.OCSPVerifier;
import cc.abstra.trantor.security.certificate.ocsp.exceptions.OCSPAccessLocationException;
import cc.abstra.trantor.security.certificate.ocsp.exceptions.OCSPClientException;
import cc.abstra.trantor.security.certificate.ocsp.exceptions.OCSPProxyException;
import cc.abstra.trantor.security.utils.Utils;
import org.junit.Before;
import org.junit.Test;

import javax.naming.NamingException;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.HashSet;
import java.util.Set;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNotNull;

public class CertificateVerifierIT {

    private Set<X509Certificate> trustedCertificates = new HashSet<>();
    private Certificate testCertificate;
    private Certificate revokedCert;
    private Certificate revokedCertCA;
    private Certificate noRevocationInfoCert;
    private Certificate noRevocationInfoCertCA;
    private Certificate noRevocationInfoCertRootCA;

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

        KeyStore validKeyStore = helpers.readCertStoreResource("test.p12", "PKCS12", "secret");
        String alias1 = validKeyStore.aliases().nextElement();
        testCertificate = validKeyStore.getCertificate(alias1);

        // The certs below come from : https://test-sspev.verisign.com:2443/
        revokedCert = helpers.readX509Pubkey("revoked.der");
        revokedCertCA = helpers.readX509Pubkey("revoked_ca.der");

        // The certs below come from : http://www.madrid.org/arquitecturasw/home/item/128-certificados-digitales-pruebas
        noRevocationInfoCert = helpers.readX509Pubkey("no_revocation_info.der");
        noRevocationInfoCertCA = helpers.readX509Pubkey("no_revocation_info_ca.der");
        noRevocationInfoCertRootCA = helpers.readX509Pubkey("no_revocation_info_root.der");

    }

    @Test
    public void testVerifyCertificateWithValidCertAndOCSPValidation() throws CertificateVerificationException,
            OCSPAccessLocationException, UnknownTrustException {

        PKIXCertPathBuilderResult cp = CertificateVerifier.
                verifyCertificate((X509Certificate) testCertificate, trustedCertificates);
        assertNotNull(cp.getCertPath());
        assertNotNull(cp.getTrustAnchor());
    }

    @Test
    public void testVerifyCertificateWithValidCertAndCRLValidation() throws CertificateVerificationException,
            OCSPAccessLocationException, CRLAccessLocationException, UnknownTrustException {


        PKIXCertPathBuilderResult cp = CertificateVerifier.
                verifyCertificate((X509Certificate) testCertificate, trustedCertificates, true);
        assertNotNull(cp.getCertPath());
        assertNotNull(cp.getTrustAnchor());
    }

    @Test
    public void testVerifyCertificateWithNoRevocationInfo() throws CertificateVerificationException {
        Set<X509Certificate> caCertificates = new HashSet<>();
        caCertificates.add((X509Certificate) noRevocationInfoCertCA);
        caCertificates.add((X509Certificate) noRevocationInfoCertRootCA);

        try {
            CertificateVerifier.verifyCertificate((X509Certificate) noRevocationInfoCert, caCertificates);
        } catch (UnknownTrustException e) {
            assertEquals(noRevocationInfoCert, e.getCertPathBuilderResult().getCertPath().getCertificates().get(0));
            assertEquals(noRevocationInfoCertRootCA, e.getCertPathBuilderResult().getTrustAnchor().getTrustedCert());
        }
    }

    @Test
    public void testVerifyRevokedCertViaOCSPandHTTP() throws CertificateException, OCSPClientException,
            OCSPProxyException {
        Utils.addBCProvider();
        String ocspServerStringUrl = OCSPVerifier.getAccessLocation((X509Certificate)revokedCert);
        OCSPClient ocspClient = new OCSPClient(ocspServerStringUrl);
        OCSPResponse respuesta = ocspClient.validateCert((X509Certificate)revokedCert, (X509Certificate)revokedCertCA);
        OCSPStatus bloque = new OCSPStatus(respuesta, (X509Certificate)revokedCert);
        assertEquals(ICertStatus.CERT_STATUS.revoked, bloque.getStatus());
    }

    @Test(expected = CertificateVerificationException.class)
    public void testVerifyRevokedCertViaCRLandHTTP() throws CRLAccessLocationException,
            CertificateVerificationException {
        Utils.addBCProvider();
        CRLVerifier.verifyCertificate((X509Certificate)revokedCert);
    }

    @Test(expected = OCSPClientException.class)
    public void testVerifyRevokedCertViaOCSPandWrongResponder() throws CertificateException, OCSPProxyException,
            OCSPClientException {
        Utils.addBCProvider();

        String ocspServerStringUrl = "http://example.net";  //HTTP
        OCSPClient ocspClient = new OCSPClient(ocspServerStringUrl);
        ocspClient.validateCert((X509Certificate)revokedCert, (X509Certificate)revokedCertCA);
    }


    @Test(expected = OCSPClientException.class)
    public void testVerifyRevokedCertViaOCSPandUnreachableResponder() throws CertificateException, OCSPProxyException,
            OCSPClientException {

        Utils.addBCProvider();

        String ocspServerStringUrl = "http://bogus.abstra.cc";
        OCSPClient ocspClient = new OCSPClient(ocspServerStringUrl);
        ocspClient.validateCert((X509Certificate) revokedCert, (X509Certificate) revokedCertCA);
    }

    @Test(expected =  java.security.cert.CRLException.class)
    public void testVerifyRevokedCertViaCRLandWrongEndpoint() throws CertificateException, CRLClientException,
            CRLException, NamingException {
        CRLVerifier.downloadCRL("http://example.net");
    }


    @Test(expected = CRLClientException.class)
    public void testVerifyRevokedCertViaCRLandUnreachableEndpoint() throws CertificateException, CRLClientException,
            CRLException, NamingException {

        CRLVerifier.downloadCRL("http://bogus.abstra.cc");
    }
}
