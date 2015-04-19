package tools.pki.gbay.crypto.provider;

import java.io.IOException;
import java.security.cert.X509Certificate;

import tools.pki.gbay.crypto.keys.validation.CertificateIssuer;
import tools.pki.gbay.crypto.keys.validation.IssuerPropertyFile;
import tools.pki.gbay.errors.GbayCryptoException;

import org.apache.log4j.Logger;

public class ScanCaFinder implements CaFinderInterface{
	IssuerPropertyFile myFile;
	Logger log = Logger.getLogger(ScanCaFinder.class);

	public ScanCaFinder(IssuerPropertyFile issuerPropertyFile) throws IOException {
		if (issuerPropertyFile == null){
			log.debug("You sent a null property file to CA Finder we get the instance of ours...");
			myFile = IssuerPropertyFile.getInstance();
		}
		else{
			myFile = issuerPropertyFile;
		}
		log.debug(""+ myFile.getAllIssuers().size() + " issuers is in ca finder");

	}

	@Override
	public CertificateIssuer getIssuer(X509Certificate currentCert)
			throws GbayCryptoException {
		log.debug("CA finder is looking for issuer of " + currentCert.getSubjectDN());
		return myFile.getIssuer(currentCert);
	}

}
