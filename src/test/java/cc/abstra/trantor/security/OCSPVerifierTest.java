package cc.abstra.trantor.security;

import cc.abstra.trantor.security.certificate.ICertStatus;
import cc.abstra.trantor.security.certificate.ocsp.OCSPClient;
import cc.abstra.trantor.security.certificate.ocsp.OCSPResponse;
import cc.abstra.trantor.security.certificate.ocsp.OCSPStatus;
import cc.abstra.trantor.security.certificate.ocsp.OCSPVerifier;
import cc.abstra.trantor.security.certificate.ocsp.exceptions.OCSPAccessLocationException;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.*;
import static org.powermock.api.support.membermodification.MemberMatcher.method;
import static org.powermock.api.support.membermodification.MemberModifier.stub;

@PrepareForTest({OCSPVerifier.class})
@RunWith(PowerMockRunner.class)
public class OCSPVerifierTest {

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
    public void verifyCertificateWithOCSPInfo() throws Exception {
        //Mocks
        spy(OCSPVerifier.class);
        OCSPClient mockOCSPClient = mock(OCSPClient.class);
        OCSPResponse mockOCSPResponse = mock(OCSPResponse.class);
        OCSPStatus mockOCSPStatus = mock(OCSPStatus.class);

        PKIXCertPathBuilderResult pkixCertPathBuilderResult = mock(PKIXCertPathBuilderResult.class);
        final X509Certificate clientCert = mock(X509Certificate.class);
        final X509Certificate caCert = mock(X509Certificate.class);
        final List<X509Certificate> aCertPathTuple = new ArrayList<X509Certificate>(){{
            add(clientCert);
            add(caCert);
        }};
        List<List<X509Certificate>> certPathTuples = new ArrayList<List<X509Certificate>>(){{
            add(aCertPathTuple);
        }};

        stub(method(OCSPVerifier.class, "getCompleteCertChain")).toReturn(certPathTuples);

        doReturn("http://ocsp1.example.net").when(OCSPVerifier.class, "getAccessLocation", clientCert);
        doReturn("http://ocsp.example.net/ca").when(OCSPVerifier.class, "getAccessLocation", caCert);

        whenNew(OCSPClient.class).withArguments(anyString()).thenReturn(mockOCSPClient);
        when(mockOCSPClient.validateCert(clientCert, caCert)).thenReturn(mockOCSPResponse);
        whenNew(OCSPStatus.class).withArguments(mockOCSPResponse, clientCert).thenReturn(mockOCSPStatus);
        when(mockOCSPStatus.getStatus()).thenReturn(ICertStatus.CERT_STATUS.valid);

        OCSPVerifier.verifyCertificate(pkixCertPathBuilderResult);

    }

    @Ignore("pending test")
    @Test
    public void verifyCertificateWithNoOCSPInfo() {
        //fail("PENDING (use PowerMock here)");
    }

    @Test
    public void testGetAccessLocationWithCertWithOCSPInfo() throws OCSPAccessLocationException, CertificateException {
        String ocspUrl = OCSPVerifier.getAccessLocation((X509Certificate)testCertificate);
        assertEquals("http://ocsp.startssl.com/sub/class1/client/ca", ocspUrl);
    }

    @Test
    public void testGetAccessLocationWithCertWithNoOCSPInfo() throws OCSPAccessLocationException, CertificateException {
        String ocspUrl = OCSPVerifier.getAccessLocation((X509Certificate) selfSignedCertificate);
        assertTrue(ocspUrl.isEmpty());
    }

}
