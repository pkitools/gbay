package tools.pki.gbay.hardware.provider;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import tools.pki.gbay.crypto.keys.CertificateInterface;
import tools.pki.gbay.crypto.keys.CertificateValiditor;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;

public class PKCS11SupplierData {
	public String cryptokiLib;
	public boolean forcingCryptoki;
	public CMSSignedData signingResult;
	public String plainText;
	public String pin;
	public boolean makeDigestOnToken;
	public String digestionAlgorithm;
	public String encryptionAlgorithm;
	public boolean encapsulate;
	public String filePath;
	private List<CertificateInterface> certs = new ArrayList<CertificateInterface>();

	public PKCS11SupplierData(String cryptokiLib, boolean forcingCryptoki,
			CMSSignedData signingResult, boolean makeDigestOnToken,
			String digestionAlgorithm, String encryptionAlgorithm,
			String filePath) {
		this.cryptokiLib = cryptokiLib;
		this.forcingCryptoki = forcingCryptoki;
		this.signingResult = signingResult;
		this.makeDigestOnToken = makeDigestOnToken;
		this.digestionAlgorithm = digestionAlgorithm;
		this.encryptionAlgorithm = encryptionAlgorithm;
		this.filePath = filePath;
	}

	/**
	 * @return the certs
	 * @throws CertificateException 
	 */
	public List<CertificateInterface> getCerts() throws CertificateException {

		 Store                   certStore = signingResult.getCertificates();
		  SignerInformationStore  signers = signingResult.getSignerInfos();
		  Collection<?>              c = signers.getSigners();
		  Iterator<?>                it = c.iterator();
		  
		  while (it.hasNext())
		  {
		      SignerInformation   signer = (SignerInformation)it.next();
		      Collection<?>          certCollection = certStore.getMatches(signer.getSID());

		      Iterator<?>              certIt = certCollection.iterator();
		  	X509Certificate includedCert = new JcaX509CertificateConverter()
			.getCertificate((X509CertificateHolder) certIt
					.next());
		  certs.add(new CertificateValiditor(includedCert));
		  }
		 
		return certs;
	}
}