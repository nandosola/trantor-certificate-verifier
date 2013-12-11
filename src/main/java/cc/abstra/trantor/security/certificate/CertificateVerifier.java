package cc.abstra.trantor.security.certificate;

import cc.abstra.trantor.security.APIConstants;
import cc.abstra.trantor.security.certificate.crl.CRLVerifier;
import cc.abstra.trantor.security.certificate.crl.exceptions.CRLAccessLocationException;
import cc.abstra.trantor.security.certificate.exceptions.CertificateVerificationException;
import cc.abstra.trantor.security.certificate.exceptions.UnknownTrustException;
import cc.abstra.trantor.security.certificate.ocsp.OCSPVerifier;
import cc.abstra.trantor.security.certificate.ocsp.exceptions.OCSPAccessLocationException;
import cc.abstra.trantor.security.utils.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.cert.*;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Class for building a certification chain for given certificate and verifying
 * it. Relies on a set of root CA certificates and intermediate certificates
 * that will be used for building the certification chain. The verification
 * process assumes that all self-signed certificates in the set are trusted
 * root CA certificates and all other certificates in the set are intermediate
 * certificates.
 *
 * The certificate to be validated does not necessarily have the
 *
 * @author Svetlin Nakov
 * @author Nando Sola
 * @see <a href="http://www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle">X.509 Certificate Validation in Java: Build and Verify Chain and Verify CLR with Bouncy Castle</a>
 * @see <a href="http://codeautomate.org/blog/2012/02/certificate-validation-using-java">X.509 Certificate Validation Using Java</a>
 */
public class CertificateVerifier {

    //TODO verify that certificate is valid for signing purposes

    static {
        Utils.addBCProvider();
    }

    private static final Logger LOG = Logger.getLogger(CertificateVerifier.class.getName());


    /**
     * Attempts to build a certification chain for given certificate and to verify
     * it. Relies on a set of root CA certificates and intermediate certificates
     * that will be used for building the certification chain. The verification
     * process assumes that all self-signed certificates in the set are trusted
     * root CA certificates and all other certificates in the set are intermediate
     * certificates.
     *
     * @param cert - certificate for validation
     * @param additionalCerts - set of trusted root CA certificates that will be
     * 		used as "trust anchors" and intermediate CA certificates that will be
     * 		used as part of the certification chain. All self-signed certificates
     * 		are considered to be trusted root CA certificates. All the rest are
     * 		considered to be intermediate CA certificates.
     * @return the certification chain (if verification is successful)
     * @throws cc.abstra.trantor.security.certificate.exceptions.CertificateVerificationException - if the certification is not
     * 		successful (e.g. certification path cannot be built or some
     * 		certificate in the chain is expired or CRL checks are failed)
     */
    public static PKIXCertPathBuilderResult verifyCertificate(X509Certificate cert,
                                                              Set<X509Certificate> additionalCerts)
            throws CertificateVerificationException, UnknownTrustException {

        return verifyCertificate(cert, additionalCerts, false);
    }

    /**
     * <code>verifyCertificate</code> overload for testing
     *
     * @param verifyOnlyCRL - use this arg for your integration tests
     */
    public static PKIXCertPathBuilderResult verifyCertificate(X509Certificate cert,
                                                              Set<X509Certificate> additionalCerts,
                                                              boolean verifyOnlyCRL)
            throws CertificateVerificationException, UnknownTrustException {

        try {
            if (null == cert)
                throw new CertificateVerificationException("The certificate has no value. Please check your password");

            if (hasExpired(cert))
                throw new CertificateVerificationException("The certificate expired on: "+cert.getNotAfter());

            // Check for self-signed certificate
            if (isSelfSigned(cert))
                throw new CertificateVerificationException("The certificate is self-signed.");

            // Prepare a set of trusted root CA certificates
            // and a set of intermediate certificates
            Set<X509Certificate> trustedRootCerts = new HashSet<>();
            Set<X509Certificate> intermediateCerts = new HashSet<>();
            for (X509Certificate additionalCert : additionalCerts) {
                if (isSelfSigned(additionalCert)) {
                    trustedRootCerts.add(additionalCert);
                } else {
                    intermediateCerts.add(additionalCert);
                }
            }

            LOG.info("Attempting to build the certification chain and verify it");
            PKIXCertPathBuilderResult verifiedCertChain = verifyCertificate(cert, trustedRootCerts, intermediateCerts);

            if (verifyOnlyCRL) {
                verifyCRL(cert, verifiedCertChain);
            } else {
                try {
                    LOG.info("Trying to verify via OCSP");
                    OCSPVerifier.verifyCertificate(verifiedCertChain);
                } catch (OCSPAccessLocationException ocspEx) {
                    LOG.warning("Certificate has no OCSP endpoints. Using CRL method");
                    verifyCRL(cert, verifiedCertChain);
                }
            }

            // The chain is built and verified. Return it as a result
            return verifiedCertChain;
        } catch (InvalidAlgorithmParameterException iapEx) {
            throw new CertificateVerificationException(
                    "No CA has been found: " +
                            cert.getSubjectX500Principal(), iapEx);
        } catch (CertPathBuilderException certPathEx) {
            throw new CertificateVerificationException(
                    "Error building certification path: " +
                            cert.getSubjectX500Principal(), certPathEx);
        } catch (CertificateVerificationException cvex) {
            throw cvex;
        } catch (Exception ex) {
            if (ex instanceof UnknownTrustException) {
                throw (UnknownTrustException)ex;
            } else {
                throw new CertificateVerificationException(
                        "Error verifying the certificate: " +
                                cert.getSubjectX500Principal(), ex);
            }
        }
    }

    private static void verifyCRL(X509Certificate cert, PKIXCertPathBuilderResult certPathBuilderResult)
            throws CertificateVerificationException, UnknownTrustException {
        try {
            LOG.info("Verifying via CRL");
            CRLVerifier.verifyCertificate(cert);
        } catch (CRLAccessLocationException crlEx) {
            LOG.warning("Couldn't find CRL distribution points either");
            throw new UnknownTrustException("Cannot trust on this certificate chain", certPathBuilderResult);
        }
    }

    /**
     * Checks whether given X.509 certificate has expired.
     */
    public static boolean hasExpired(X509Certificate cert) {
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException e) {
            return true;
        } catch (CertificateNotYetValidException e) {
            return false;
        }
        return false;
    }

    /**
     * Checks whether given X.509 certificate is self-signed.
     */
    public static boolean isSelfSigned(X509Certificate cert)
            throws CertificateException, NoSuchAlgorithmException,
            NoSuchProviderException {
        try {
            // Try to verify certificate signature with its own public key
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
            return true;
        } catch (SignatureException sigEx) {
            // Invalid signature --> not self-signed
            return false;
        } catch (InvalidKeyException keyEx) {
            // Invalid key --> not self-signed
            return false;
        }
    }

    /**
     * Attempts to build a certification chain for given certificate and to verify
     * it. Relies on a set of root CA certificates (trust anchors) and a set of
     * intermediate certificates (to be used as part of the chain).
     * @param cert - certificate for validation
     * @param allTrustedRootCerts - set of trusted root CA certificates
     * @param allIntermediateCerts - set of intermediate certificates
     * @return the certification chain (if verification is successful)
     * @throws GeneralSecurityException - if the verification is not successful
     * 		(e.g. certification path cannot be built or some certificate in the
     * 		chain is expired)
     */
    private static PKIXCertPathBuilderResult verifyCertificate(X509Certificate cert,
                                                               Set<X509Certificate> allTrustedRootCerts,
                                                               Set<X509Certificate> allIntermediateCerts)
            throws GeneralSecurityException {

        // Create the selector that specifies the starting certificate
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(cert);

        // Create the trust anchors (set of root CA certificates)
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        for (X509Certificate trustedRootCert : allTrustedRootCerts) {
            trustAnchors.add(new TrustAnchor(trustedRootCert, null));
        }

        // Configure the PKIX certificate builder algorithm parameters
        PKIXBuilderParameters pkixParams;
        try {
            pkixParams = new PKIXBuilderParameters(trustAnchors, selector);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new InvalidAlgorithmParameterException("No root CA has been found for this certificate", ex);
        }

        // Disable CRL checks (this is done manually as additional step)
        pkixParams.setRevocationEnabled(false);

        // Add all certs so that the chain can be constructed
        pkixParams.addCertStore(createCertStore(cert));
        pkixParams.addCertStore(createCertStore(allIntermediateCerts));
        pkixParams.addCertStore(createCertStore(allTrustedRootCerts));

        // Build and verify the certification chain
        CertPathBuilder builder = CertPathBuilder.getInstance(CertPathBuilder.getDefaultType(), APIConstants.PROVIDER_BC_NAME);
        return (PKIXCertPathBuilderResult) builder.build(pkixParams);
    }

    private static CertStore createCertStore(X509Certificate certificate) throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException {
        Set<X509Certificate> certificateSet = new HashSet<>();
        certificateSet.add(certificate);
        return createCertStore(certificateSet);
    }

    private static CertStore createCertStore(Set<X509Certificate> certificateSet) throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException {
        return CertStore.getInstance("Collection", new CollectionCertStoreParameters(certificateSet), APIConstants.PROVIDER_BC_NAME);
    }
}