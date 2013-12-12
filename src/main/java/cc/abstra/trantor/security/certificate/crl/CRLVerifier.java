package cc.abstra.trantor.security.certificate.crl;

import cc.abstra.trantor.security.certificate.crl.exceptions.CRLAccessLocationException;
import cc.abstra.trantor.security.certificate.crl.exceptions.CRLClientException;
import cc.abstra.trantor.security.certificate.exceptions.CertificateVerificationException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.X509Extension;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Logger;

/**
 * Class that verifies CRLs for given X509 certificate. Extracts the CRL
 * distribution points from the certificate (if available) and checks the
 * certificate revocation status against the CRLs coming from the
 * distribution points. Supports HTTP, HTTPS, FTP and LDAP based URLs.
 *
 * @author Svetlin Nakov
 */
public class CRLVerifier {

    //TODO use http/ftp commons, with SSL support & extract to CRLClient.class
    //TODO verifyCertificate should check a complete PKIXCertPathBuilderResult pkixCertPath?
    private static final Logger LOG = Logger.getLogger(CRLVerifier.class.getName());

    /**
     * Extracts the CRL distribution points from the certificate (if available)
     * and checks the certificate revocation status against the CRLs coming from
     * the distribution points. Supports HTTP, HTTPS, FTP and LDAP based URLs.
     *
     * @param cert the certificate to be checked for revocation
     * @throws CertificateVerificationException if the certificate is revoked
     */
    public static void verifyCertificate(X509Certificate cert)
            throws CertificateVerificationException, CRLAccessLocationException {
        try {
            List<String> crlDistPoints = getAccessLocation(cert);
            if (crlDistPoints.isEmpty()) {
                throw new CRLAccessLocationException("OCSP endpoint information is missing");
            }
            for (String crlDP : crlDistPoints) {
                X509CRL crl = downloadCRL(crlDP);
                if (crl.isRevoked(cert)) {
                    LOG.info("The certificate is revoked by CRL: " + crlDP);
                    throw new CertificateVerificationException(
                            "The certificate is revoked by CRL: " + crlDP);
                }
                LOG.info("The certificate looks good!");
            }
        } catch (Exception ex) {
            if (ex instanceof CRLClientException || ex instanceof  java.security.cert.CRLException) {
                //TODO should OCSPClientException mean UnknownTrust?
                throw new CertificateVerificationException("The client could not retrieve the CRL information", ex);
            } else if (ex instanceof CRLAccessLocationException) {
                throw (CRLAccessLocationException) ex;
            }
            else {
                throw new CertificateVerificationException(
                        "Can not verify CRL for certificate: " +
                                cert.getSubjectX500Principal() + "\n" + ex.getMessage());
            }
        }
    }

    /**
     * Downloads CRL from given URL. Supports http, https, ftp and ldap based URLs.
     */
    public static X509CRL downloadCRL(String crlURL) throws
            CertificateException, java.security.cert.CRLException, NamingException, CRLClientException {
        if (crlURL.startsWith("http://") || crlURL.startsWith("https://")
                || crlURL.startsWith("ftp://")) {
            X509CRL crl = downloadCRLFromWeb(crlURL);
            return crl;
        } else if (crlURL.startsWith("ldap://")) {
            X509CRL crl = downloadCRLFromLDAP(crlURL);
            return crl;
        } else {
            throw new CRLClientException(
                    "Can not download CRL from certificate " +
                            "distribution point: " + crlURL);
        }
    }

    /**
     * Downloads a CRL from given LDAP url, e.g.
     * ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
     */
    private static X509CRL downloadCRLFromLDAP(String ldapURL)
            throws CertificateException, NamingException, CRLClientException, java.security.cert.CRLException {
        Hashtable<String , String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY,
                "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapURL);

        DirContext ctx = new InitialDirContext(env);
        Attributes avals = ctx.getAttributes("");
        Attribute aval = avals.get("certificateRevocationList;binary");
        byte[] val = (byte[])aval.get();
        if ((val == null) || (val.length == 0)) {
            throw new CRLClientException(
                    "Can not download CRL from: " + ldapURL);
        } else {
            InputStream inStream = new ByteArrayInputStream(val);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL)cf.generateCRL(inStream);
            return crl;
        }
    }

    /**
     * Downloads a CRL from given HTTP/HTTPS/FTP URL, e.g.
     * http://crl.infonotary.com/crl/identity-ca.crl
     */
    private static X509CRL downloadCRLFromWeb(String crlURL) throws CertificateException,
            java.security.cert.CRLException, CRLClientException {

        InputStream crlStream;
        try {
            URL url = new URL(crlURL);
            crlStream = url.openStream();
        } catch (IOException e) {
            throw new CRLClientException("Couldn't open remote endpoint: "+crlURL);
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(crlStream);
            return crl;
        } finally {
            try {
                crlStream.close();
            } catch (IOException e) {
                e.printStackTrace();
                //do nothing
            }
        }
    }

    /**
     * Extracts all CRL distribution point URLs from the "CRL Distribution Point"
     * extension in a X.509 certificate. If CRL distribution point extension is
     * unavailable, returns an empty list.
     */
    public static List<String> getAccessLocation(
            X509Certificate cert) throws CertificateException {
        byte[] crldpExt = cert.getExtensionValue(X509Extension.cRLDistributionPoints.getId());

        if (crldpExt == null) {
            List<String> emptyList = new ArrayList<>();
            return emptyList;
        }

        List<String> crlUrls = new ArrayList<>();

        try {
            ASN1InputStream oAsnInStream = new ASN1InputStream(
                    new ByteArrayInputStream(crldpExt));
            ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
            DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
            byte[] crldpExtOctets = dosCrlDP.getOctets();
            ASN1InputStream oAsnInStream2 = new ASN1InputStream(
                    new ByteArrayInputStream(crldpExtOctets));
            ASN1Primitive derObj2 = oAsnInStream2.readObject();
            CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);

            for (DistributionPoint dp : distPoint.getDistributionPoints()) {
                DistributionPointName dpn = dp.getDistributionPoint();
                // Look for URIs in fullName
                if (dpn != null) {
                    if (dpn.getType() == DistributionPointName.FULL_NAME) {
                        GeneralName[] genNames = GeneralNames.getInstance(
                                dpn.getName()).getNames();
                        // Look for an URI
                        for (int j = 0; j < genNames.length; j++) {
                            if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
                                String url = DERIA5String.getInstance(
                                        genNames[j].getName()).getString();
                                crlUrls.add(url);
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            throw new CertificateException("Found CRL attributes, but couldn't read them. "+
                    "The cert might be corrupted or tampered with!");
        }
        return crlUrls;
    }

}
