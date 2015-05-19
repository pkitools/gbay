package tools.pki.gbay.test.signature;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import tools.pki.gbay.crypto.provider.CrlFinderInterface;

public class Crlcaller implements CrlFinderInterface {
	
	@Override
	public X509CRL getCrl(X509Certificate cert) {
		
		return null;
	}

}
