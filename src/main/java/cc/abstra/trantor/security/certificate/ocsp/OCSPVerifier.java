package cc.abstra.trantor.security.certificate.ocsp;

import cc.abstra.trantor.security.certificate.ICertStatus;
import cc.abstra.trantor.security.certificate.exceptions.CertificateVerificationException;
import cc.abstra.trantor.security.certificate.ocsp.exceptions.OCSPAccessLocationException;
import cc.abstra.trantor.security.certificate.ocsp.exceptions.OCSPClientException;
import cc.abstra.trantor.security.certificate.ocsp.exceptions.OCSPProxyException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.X509Extension;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;
import java.util.logging.Logger;

public class OCSPVerifier {

    private static final Logger LOG = Logger.getLogger(OCSPVerifier.class.getName());

    public static void verifyCertificate(PKIXCertPathBuilderResult pkixCertPath)
            throws CertificateVerificationException, OCSPAccessLocationException {
        List<ICertStatus> result = new ArrayList<>();

        try {
            for (List<X509Certificate> certTuple : getCompleteCertChain(pkixCertPath)) {
                X509Certificate certificateToValidate = certTuple.get(0);
                X509Certificate issuerCertificate = certTuple.get(1);

                String ocspServerStringUrl = getAccessLocation(certificateToValidate);
                if (ocspServerStringUrl.isEmpty()){
                    throw new OCSPAccessLocationException("OCSP endpoint information is missing");
                }

                OCSPClient ocspClient = new OCSPClient(ocspServerStringUrl);
                OCSPResponse respuesta = ocspClient.validateCert(certificateToValidate, issuerCertificate);
                OCSPStatus bloque = new OCSPStatus(respuesta, certificateToValidate);
                result.add(bloque);
            }

        } catch (OCSPClientException | OCSPProxyException | CertificateException ex) {
            //TODO should OCSPClientException mean UnknownTrust?
            throw new CertificateVerificationException(ex.getMessage(), ex);
        }

        for (ICertStatus certStatus : result) {
            if (ICertStatus.CERT_STATUS.valid != certStatus.getStatus()) {
                throw new CertificateVerificationException("The certificate is not valid. Got status: "+
                        certStatus.getStatus());
            }
        }
        LOG.info("The certificate looks good!");
    }

    private static List<List<X509Certificate>> getCompleteCertChain(PKIXCertPathBuilderResult pkixCertPath)
            throws CertificateException {
        List<List<X509Certificate>> certificateList = new ArrayList<>();

        List<Certificate> certificatePath = new ArrayList<>();
        X509Certificate rootCaCert = pkixCertPath.getTrustAnchor().getTrustedCert();

        certificatePath.addAll(pkixCertPath.getCertPath().getCertificates());
        certificatePath.add(rootCaCert);

        int certificatesSize = certificatePath.size();
        if (1 == certificatesSize) {
            throw new CertificateException("Certificate Path insufficient size: must be at least 2");
        }
        for (int i = 0; i < certificatesSize; i++) {
            if (certificatesSize - 1 == i) {  //We've reached the root CA
                break;
            } else {
                List<X509Certificate> certTuple = new ArrayList<>(2);
                certTuple.add((X509Certificate)certificatePath.get(i));
                certTuple.add((X509Certificate)certificatePath.get(i+1));
                certificateList.add(certTuple);
            }
        }
        return certificateList;
    }

    public static String getAccessLocation(X509Certificate certificate) throws CertificateException {

        byte[] authInfoAccessExtensionValue = certificate.getExtensionValue(X509Extension.authorityInfoAccess
                .getId());
        if (null == authInfoAccessExtensionValue) {
            return "";
        }
        AuthorityInformationAccess authorityInformationAccess = null;

        try {
            DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(
                    authInfoAccessExtensionValue)).readObject());

            ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(oct.getOctets()));
            authorityInformationAccess = AuthorityInformationAccess.getInstance(seq);

        } catch (IOException e) {
            throw new CertificateException("Found OCSP endpoint attrs, but couldn't read them. "+
                    "The cert might be corrupted or tampered with!");
        }

        AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
        for (AccessDescription accessDescription : accessDescriptions) {
            LOG.fine("access method: " + accessDescription.getAccessMethod());
            boolean correctAccessMethod = accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.ocspAccessMethod);
            if (!correctAccessMethod) {
                continue;
            }
            GeneralName gn = accessDescription.getAccessLocation();
            if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) {
                LOG.fine("not a uniform resource identifier");
                continue;
            }
            DERIA5String str = (DERIA5String) ((DERTaggedObject) gn.toASN1Primitive()).getObject();
            String accessLocation = str.getString();
            LOG.fine("access location: " + accessLocation);
            return accessLocation;
        }
        return null;

    }


}
