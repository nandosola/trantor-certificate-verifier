package cc.abstra.trantor.security;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class TestHelpers {

    private final Class resourceClass;

    public TestHelpers(Class resourceClass) {
        this.resourceClass = resourceClass;
    }

    public KeyStore readCertStoreResource(String resourceName, String storeType, String storePassword)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {

        URL certStoreUrl = resourceClass.getResource("/"+resourceName);
        InputStream certStoreIS = certStoreUrl.openStream();
        KeyStore ks = KeyStore.getInstance(storeType);
        ks.load(certStoreIS, storePassword.toCharArray());
        certStoreIS.close();
        return ks;
    }

    public Certificate readX509Pubkey(String resourceName) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {

        URL certStoreUrl = resourceClass.getResource("/"+resourceName);
        InputStream certStoreIS = certStoreUrl.openStream();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        Certificate c = cf.generateCertificate(certStoreIS);
        certStoreIS.close();

        return c;
    }
}
