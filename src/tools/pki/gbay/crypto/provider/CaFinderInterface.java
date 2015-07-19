package tools.pki.gbay.crypto.provider;

import java.security.cert.X509Certificate;

import tools.pki.gbay.crypto.keys.validation.CertificateChain;
import tools.pki.gbay.errors.CryptoException;

/**
 * Interface to find issuer of a cert, please implement this interface if you have a service or other way around for providing an issuer
 * @author Android
 *
 */
public interface CaFinderInterface {
	/**
	 * Get CA certs of a specific certificate
	 * @param currentCert the certificate you want to get chain
	 * @return certificate chain
	 * @throws CryptoException
	 */
 CertificateChain getIssuer(X509Certificate currentCert) throws CryptoException;
}
