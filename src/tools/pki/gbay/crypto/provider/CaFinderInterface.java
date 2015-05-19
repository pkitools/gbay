package tools.pki.gbay.crypto.provider;

import java.security.cert.X509Certificate;

import tools.pki.gbay.crypto.keys.validation.CertificateChain;
import tools.pki.gbay.errors.CryptoException;

public interface CaFinderInterface {
 CertificateChain getIssuer(X509Certificate currentCert) throws CryptoException;
}
