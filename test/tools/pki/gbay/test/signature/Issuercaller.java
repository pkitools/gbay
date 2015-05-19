package tools.pki.gbay.test.signature;

import java.security.cert.X509Certificate;

import tools.pki.gbay.crypto.keys.validation.CertificateChain;
import tools.pki.gbay.crypto.keys.validation.CertificateIssuer;
import tools.pki.gbay.crypto.provider.CaFinderInterface;
import tools.pki.gbay.errors.CryptoException;

public class Issuercaller implements CaFinderInterface {

	@Override
	public CertificateChain getIssuer(X509Certificate currentCert)
			throws CryptoException {
	//System.err.println("ssssssssssssssssssssssssssssssssssssssssssss");
		CertificateChain cc = new CertificateChain();
		cc.AddIssuer(new CertificateIssuer("araz"));
		return cc;
	}


}
