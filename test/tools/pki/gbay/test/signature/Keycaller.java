package tools.pki.gbay.test.signature;

import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.naming.NamingException;

import org.apache.log4j.Logger;

import tools.pki.gbay.crypto.keys.KeyStorage.CoupleKey;
import tools.pki.gbay.crypto.keys.validation.CertificateRevocationList;
import tools.pki.gbay.errors.CryptoException;
import tools.pki.gbay.interfaces.CrlFinderInterface;
import tools.pki.gbay.interfaces.KeySelectionInterface;

public class Keycaller implements KeySelectionInterface , CrlFinderInterface{

	private static Logger log = Logger.getLogger(Keycaller.class);

	@Override
	public Integer selectKey(List<CoupleKey> keyCouples) {
	log.debug("Returning first key couple");
		return 0;
	}

	@Override
	public X509CRL getCrl(X509Certificate cert) {
try {
	return		CertificateRevocationList.getCrlFromCert(cert);
} catch (CertificateException | CRLException | IOException | NamingException
		| CryptoException e) {
	log.error(e);
}
return null;
		
	}

}
