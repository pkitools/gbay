package tools.pki.gbay.crypto;

import tools.pki.gbay.configuration.Configuration;
import tools.pki.gbay.configuration.SecurityConcepts;
import tools.pki.gbay.crypto.keys.CertificateValiditor;
import tools.pki.gbay.crypto.keys.KeyStorage;
import tools.pki.gbay.crypto.texts.Base64;
import tools.pki.gbay.errors.GbayCryptoException;
import tools.pki.gbay.util.general.CryptoFile;

public class GbayApi  {
	private static GbayApi instance;

	protected GbayApi() {
		 new Configuration();
		SecurityConcepts.addProvider();
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
