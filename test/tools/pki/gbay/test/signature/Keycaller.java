package tools.pki.gbay.test.signature;

import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.naming.NamingException;

import tools.pki.gbay.crypto.keys.KeyStorage.CoupleKey;
import tools.pki.gbay.crypto.keys.validation.CertificateRevocationList;
import tools.pki.gbay.crypto.provider.CrlFinderInterface;
import tools.pki.gbay.crypto.provider.KeySelectionInterface;
import tools.pki.gbay.errors.CryptoException;

public class Keycaller implements KeySelectionInterface , CrlFinderInterface{

	@Override
	public Integer selectKey(List<CoupleKey> keyCouples) {
		System.err.println("hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh");
		return 0;
	}

	@Override
	public X509CRL getCrl(X509Certificate cert) {
try {
	return		CertificateRevocationList.getCrlFromCert(cert);
} catch (CertificateException | CRLException | IOException | NamingException
		| CryptoException e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
}
return null;
		
	}

}
