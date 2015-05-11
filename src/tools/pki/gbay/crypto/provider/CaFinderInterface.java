package tools.pki.gbay.crypto.provider;

import java.security.cert.X509Certificate;
import java.util.Set;

import tools.pki.gbay.crypto.keys.validation.CertificateIssuer;
import tools.pki.gbay.errors.GbayCryptoException;

public interface CaFinderInterface {
 Set<CertificateIssuer> getIssuer(X509Certificate currentCert) throws GbayCryptoException;
}
