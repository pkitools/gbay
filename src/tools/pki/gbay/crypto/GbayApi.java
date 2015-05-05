package tools.pki.gbay.crypto;

import org.apache.log4j.Logger;

import tools.pki.gbay.configuration.PropertyFileConfiguration;
import tools.pki.gbay.crypto.keys.CertificateValiditor;
import tools.pki.gbay.crypto.keys.KeyStorage;
import tools.pki.gbay.crypto.provider.SignatureSettingInterface;
import tools.pki.gbay.crypto.provider.SoftCert;
import tools.pki.gbay.crypto.texts.Base64;
import tools.pki.gbay.crypto.texts.PlainText;
import tools.pki.gbay.crypto.texts.SignedText;
import tools.pki.gbay.crypto.texts.VerifiedText;
import tools.pki.gbay.errors.GbayCryptoException;
import tools.pki.gbay.util.general.CryptoFile;

import com.google.inject.Inject;
import com.google.inject.Singleton;

@Singleton
public class GbayApi  {
	private static final Logger logger = Logger.getLogger(GbayApi.class);

	private static GbayApi instance;

	@Inject
	private SignatureSettingInterface settings;
	 //setter method injector
    
	protected GbayApi() {
		
		 new PropertyFileConfiguration();
	//	SecurityConcepts.addProvider();
	}

	public SignedText sign(byte[]pfx,String pin,String messageToSign) throws GbayCryptoException{

		SoftCert sc = new SoftCert(new KeyStorage(pin.toCharArray(),new PlainText(pfx)));
		SignedText st =	sc.sign(new PlainText(messageToSign));
	//	st.toBase64()
		return st;
	}
	
	public VerifiedText verify(String originalText,byte[] signedtext) throws GbayCryptoException{
		
		logger.info("Verify function is called from API...");
		logger.debug("Original Text : "+ originalText + "   SignedText:" + new String(signedtext) );
		SignedText st = new SignedText(originalText, signedtext);
		logger.debug("Signed Text Object Generated" + PropertyFileConfiguration.StarLine);
		SoftCert sc = new SoftCert();
		logger.debug("SoftCert Object Generated" + PropertyFileConfiguration.StarLine);
		
		return	(VerifiedText) st.verify(sc);
		
		
	}
	
	public  class P12Files extends KeyStorage {

		public P12Files(CryptoFile file) throws GbayCryptoException {
			super(file);
		}

		public P12Files(Base64 fileContent, char[] pin) throws GbayCryptoException {
			super(pin, fileContent);
		}

	}

	public class CertFile extends CertificateValiditor {
		public CertFile(CryptoFile file) throws GbayCryptoException {
			super(file);
		}
		
		public CertFile(Base64 fileContent) throws GbayCryptoException{
			super(fileContent.decode());
		}
	}

	public static GbayApi getInstance() {
		if (instance == null)
			instance = new GbayApi();
		return instance;
	}
}
