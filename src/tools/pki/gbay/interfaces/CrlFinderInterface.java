package tools.pki.gbay.interfaces;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

/**
 * Interface to get the CRL for a cert, implement this Interface if you have some service or way around for downloading CRL
 * @author Android
 *
 */
public interface CrlFinderInterface {

	/**
	 * CRL of the Certificate
	 * @param cert
	 * @return CRL
	 */
	X509CRL getCrl(X509Certificate cert);

}
