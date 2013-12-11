package cc.abstra.trantor.security;

import cc.abstra.trantor.security.certificate.crl.CRLVerifier;
import cc.abstra.trantor.security.certificate.crl.exceptions.CRLAccessLocationException;
import cc.abstra.trantor.security.certificate.exceptions.CertificateVerificationException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.support.membermodification.MemberMatcher.method;
import static org.powermock.api.support.membermodification.MemberModifier.stub;


@RunWith(PowerMockRunner.class)
@PrepareForTest(CRLVerifier.class)
public class CRLVerifierTest {
    private Certificate testCertificate;
    private Certificate selfSignedCertificate;

    @Before
    public void setUp() throws Exception {
        TestHelpers helpers = new TestHelpers(this.getClass());

        KeyStore validKeyStore = helpers.readCertStoreResource("test.p12", "PKCS12", "secret");
        String alias1 = validKeyStore.aliases().nextElement();
        testCertificate = validKeyStore.getCertificate(alias1);

        KeyStore selfSignedKeyStore = helpers.readCertStoreResource("selfsigned.p12", "PKCS12", "secret");
        String alias2 = selfSignedKeyStore.aliases().nextElement();
        selfSignedCertificate = selfSignedKeyStore.getCertificate(alias2);
    }

    @Test
    public void verifyCertificateWithCertWithCRLInfo() throws CRLAccessLocationException,
            CertificateVerificationException {
        //Mocks
        X509CRL crl = mock(X509CRL.class);
        X509Certificate cert = mock(X509Certificate.class);

        stub(method(CRLVerifier.class, "getAccessLocation")).toReturn(new ArrayList<String>(){{
            add("http://example.net/crl1");
            add("ldap://example.net/crl2");  //triggers 2 calls to crl.isRevoked
        }});
        stub(method(CRLVerifier.class, "downloadCRL")).toReturn(crl);
        when(crl.isRevoked(eq(cert))).thenReturn(false);

        CRLVerifier.verifyCertificate(cert);
        verify(crl, times(2)).isRevoked(cert);
    }

    @Test(expected = CRLAccessLocationException.class)
    public void verifyCertificateWithNoCRLInfo() throws CRLAccessLocationException,
            CertificateVerificationException {
        //Mocks
        X509CRL crl = mock(X509CRL.class);
        X509Certificate cert = mock(X509Certificate.class);

        stub(method(CRLVerifier.class, "getAccessLocation")).toReturn(new ArrayList<>());
        stub(method(CRLVerifier.class, "downloadCRL")).toReturn(crl);
        when(crl.isRevoked(eq(cert))).thenReturn(false);

        CRLVerifier.verifyCertificate(cert);
        verify(crl).isRevoked(cert);
    }

    @Test
    public void testGetAccessLocationWithCertWithCRLInfo() throws CRLAccessLocationException, CertificateException {

        List<String> crlUrls = CRLVerifier.getAccessLocation((X509Certificate) testCertificate);
        assertEquals(1, crlUrls.size());
        assertEquals("http://crl.startssl.com/crtu1-crl.crl", crlUrls.get(0));
    }

    @Test
    public void testGetAccessLocationWithCertWithNoCRLInfo() throws CRLAccessLocationException, CertificateException {
        List<String> crlUrls = CRLVerifier.getAccessLocation((X509Certificate) selfSignedCertificate);
        assertTrue(crlUrls.isEmpty());
    }
}
