/*
 * Copyright (c) 2014, Araz
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package tools.pki.gbay.crypto.keys;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.apache.log4j.Logger;

import tools.pki.gbay.configuration.Configuration;
import tools.pki.gbay.crypto.provider.KeySelectionInterface;
import tools.pki.gbay.crypto.texts.EncodedTextInterface;
import tools.pki.gbay.crypto.texts.PlainText;
import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.GbayCryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;
import tools.pki.gbay.util.general.CryptoFile;

/**
 * 
 * @author Araz
 */
public class KeyStorage {
	Logger log = Logger.getLogger(KeyStorage.class);
	private KeyStore keyStore;
	private List<CertificateValiditor> publicKeys;
	private List<CoupleKey> keyCouples;

	private char[] pin;
	private List<String> keyAlias = new ArrayList<String>();
	private List<String> aliases = new ArrayList<String>();

	public class CoupleKey{
		Logger log = Logger.getLogger(CoupleKey.class);
		private PrivateKey privateKey;
		private char[] pin;
		private CertificateValiditor publicKey;
		private String alias;

		/**
		 * @return the privateKey
		 */
		public PrivateKey getPrivateKey() {
			return privateKey;
		}
		public CoupleKey(PrivateKey privateKey,   CertificateValiditor publicKey, String alias , char[] pin) {
			super();
			this.privateKey = privateKey;
			this.publicKey = publicKey;
			this.pin = pin;
			this.setAlias(alias);
		}
		/**
		 * @param privateKey the privateKey to set
		 */
		public void setPrivateKey(PrivateKey privateKey) {
			this.privateKey = privateKey;
		}
		/**
		 * @return the publicKey
		 */
		public CertificateValiditor getPublicKey() {
			return publicKey;
		}
		/**
		 * @param publicKey the publicKey to set
		 */
		public void setPublicKey(CertificateValiditor publicKey) {
			this.publicKey = publicKey;
		}
		/**
		 * @return the alias
		 */
		public String getAlias() {
			return alias;
		}
		/**
		 * @param alias the alias to set
		 */
		public void setAlias(String alias) {
			this.alias = alias;
		}
		
	}
	
/**
 * Generate a keystore from a string
 * @param pin Pin number of store
 * @param storeContent string representror of keystrore
 * @throws GbayCryptoException @see tools.pki.gbay.errors.GlobalErrorCode#PROVIDER_NOT_FOUND or @see tools.pki.gbay.errors.GlobalErrorCode#INVALID_ALGORITHM or @see tools.pki.gbay.errors.GlobalErrorCode#CERT_INVALID_FORMAT or @see tools.pki.gbay.errors.GlobalErrorCode#FILE_IO_ERROR or @link {@link KeyStoreException}
 */
	public KeyStorage(char[] pin, PlainText storeContent) throws GbayCryptoException  {
		this.pin = pin;
		try {
			log.info("Key Store Content : \n" + storeContent.toHexadecimalString());
			this.keyStore = getKeyStore(pin, storeContent.toByte());
			getKeyAlias(keyStore);

		} catch (KeyStoreException e) {
			throw new GbayCryptoException(e);
		} catch (NoSuchProviderException e) {
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.KEY_NOT_FOUND));
		} catch (NoSuchAlgorithmException e) {
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_ALGORITHM));
		} catch (CertificateException e) {
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT));
		} catch (IOException e) {
			e.printStackTrace();
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.FILE_IO_ERROR));

		}
}

	/**
	 * Generate a KeyStorage from a file. 
	 * <p> 
	 * Note: If p12 is having pin you need to set Pin in {@link CryptoFile} . <br>
	 * 
	 * <pre>
	 * -- Example : loading test.pfx which it's pfx pin is 12345678
	 * {@code
	 * CryptoFile file = new CryptoFile(new File("test.pfx"), "12345678");
	 * KeyStorage ks = new KeyStorage(file);
	 * }
	 * </pre>
	 * <p>
	 * @see tools.pki.gbay.util.general.CryptoFile#setPin(char[]) 
	 * @see tools.pki.gbay.util.general.CryptoFile#AegisFile(java.io.File, String) 
	 * 
	 * @param file p12 file. <i>Later on we may need to have other key stores supported</i> but now, just pfx
	 * @throws GbayCryptoException
	 */
	public KeyStorage(CryptoFile file) throws GbayCryptoException  {
		this(file.getPin(), file.toPlainText());
	}
	
	private void getKeyAlias(KeyStore keyStore2) throws  GbayCryptoException {
	try{
		getKeyAlias(keyStore2, null);
	} catch (KeyStoreException e) {
		throw new GbayCryptoException(e);
	} catch (NoSuchAlgorithmException e) {
		throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_ALGORITHM));
	
	} catch (UnrecoverableKeyException e) {
		throw new GbayCryptoException(new CryptoError(GlobalErrorCode.KEY_INVALID));
	}
	}

	/**
	 * Generate KeyStore from a base64 string
	 * @param pin pin of key
	 * @param storeContent base64 representative of key store
	 * @throws GbayCryptoException
	 */
	public KeyStorage(char[] pin, EncodedTextInterface storeContent) throws GbayCryptoException  {
try{
		this.pin = pin;
		this.keyStore = getKeyStore(pin, storeContent);
		getKeyAlias(keyStore);
} catch (KeyStoreException e) {
	throw new GbayCryptoException(e);
} catch (NoSuchProviderException e) {
	throw new GbayCryptoException(new CryptoError(GlobalErrorCode.KEY_PROVIDER_NOT_FOUND));
} catch (NoSuchAlgorithmException e) {
	throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_ALGORITHM));
} catch (CertificateException e) {
	throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT));
} catch (IOException e) {
	throw new GbayCryptoException(new CryptoError(GlobalErrorCode.FILE_IO_ERROR));

}
	}

	/**
	 * Generate a Key store from a string from an specific alias
	 * @param pin
	 * @param byteArray
	 * @param alias
	 * @throws GbayCryptoException
	 */
	public KeyStorage(char[] pin, PlainText storeContent, String alias) throws GbayCryptoException 
			 {
		try{
		this.pin = pin;
		this.keyStore = getKeyStore(pin, storeContent.toByte());
//		this.keyAlias.add(alias);
		getKeyAlias(keyStore , alias);
		
				} catch (KeyStoreException e) {
					throw new GbayCryptoException(e);
				} catch (NoSuchProviderException e) {
					throw new GbayCryptoException(new CryptoError(GlobalErrorCode.KEY_PROVIDER_NOT_FOUND));
				} catch (NoSuchAlgorithmException e) {
					throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_ALGORITHM));
				} catch (CertificateException e) {
					throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT));
				} catch (IOException e) {
					throw new GbayCryptoException(new CryptoError(GlobalErrorCode.FILE_IO_ERROR));

				} catch (UnrecoverableKeyException e) {
					throw new GbayCryptoException(new CryptoError(GlobalErrorCode.KEY_INVALID));
				}
	}

	private KeyStore getKeyStore(char[] pin, byte[] byteArray)
			throws KeyStoreException, NoSuchProviderException, IOException,
			NoSuchAlgorithmException, CertificateException {
		
		log.debug("Getting Keystore from the value" +Configuration.StarLine+Configuration.StarLine +"Byte Array Representor of Store: "+ Configuration.StarLine + new PlainText(byteArray).toHexadecimalString()+Configuration.StarLine);
		ByteArrayInputStream bis = new ByteArrayInputStream(byteArray);
		return getKeyStore(pin, bis);
	}

	private KeyStore getKeyStore(char[] pin, EncodedTextInterface byteArray)
			throws KeyStoreException, NoSuchProviderException, IOException,
			NoSuchAlgorithmException, CertificateException {
		ByteArrayInputStream bis = byteArray.toBIS();
		return getKeyStore(pin, bis);
	}

	
	
	private KeyStore getKeyStore(char[] pin, ByteArrayInputStream bis)
			throws KeyStoreException, NoSuchProviderException, IOException,
			NoSuchAlgorithmException, CertificateException {
		KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
		keystore.load(bis, pin);
		return keystore;
	}


	@SuppressWarnings("rawtypes")
	private void getKeyAlias(KeyStore keystore , String selectedAlias ) throws KeyStoreException,
			NoSuchAlgorithmException, UnrecoverableKeyException, GbayCryptoException {
		if (selectedAlias == null){
		Enumeration ale = keystore.aliases();
		this.publicKeys = new ArrayList<CertificateValiditor>();
		this.keyCouples = new ArrayList<KeyStorage.CoupleKey>();

		while (ale.hasMoreElements()) {
			String alias = (String) ale.nextElement();
			if (Configuration.DEBUG){
				log.info("Alias is found : " + alias);
			}
			addKeysofAlias(keystore, alias);
		}
		}
		else 
		{
			addKeysofAlias(keystore, selectedAlias);
		}
	}
	
	private void addKeysofAlias(KeyStore keystore, String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, GbayCryptoException{
		this.aliases.add(alias);
		if (keystore.isKeyEntry(alias)) {
			keyAlias.add(alias);
			keyCouples.add(new CoupleKey(getPrivateKey(keystore, alias,pin), new CertificateValiditor(getPublicKey(keystore, alias)), alias,pin));
		}
		else{
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.KEY_INVALID,"Invalid alias detected"));
		}

		publicKeys.add(new CertificateValiditor(getPublicKey(keystore, alias)));

	}
	
	

	private X509Certificate getPublicKey(KeyStore keystore, String alias)
			throws KeyStoreException {
		return (X509Certificate) keystore.getCertificate(alias);
	}

	private java.security.PrivateKey getPrivateKey(KeyStore keystore,
			String alias, char[] pin) throws KeyStoreException,
			NoSuchAlgorithmException, UnrecoverableKeyException {
		if (alias == null) {
			log.error("can't find a private key!");
			System.exit(0);
		}
		return (java.security.PrivateKey) keystore.getKey(alias, pin);
	}

	public List<String> getKeyAlias() {
		return keyAlias;
	}

	public List<CertificateValiditor> getPublicKeys() {
		return publicKeys;
	}

	public List<CoupleKey> getPublicKeysWithPrivateKey() {
		return keyCouples;
	}

	
/**
 * Get key couples (public and private twins)	
 * @param selectingFunction if there is more than a couple of Keys this function can be used to set which pair be 
 * @return
 * @throws GbayCryptoException
 * 
 */
	public CoupleKey getCoupleKey(KeySelectionInterface selectingFunction)
			throws GbayCryptoException {
		Integer selectedNo = 0;
		if (keyCouples.size() <= 0)
			throw new GbayCryptoException(new CryptoError(
					tools.pki.gbay.errors.GlobalErrorCode.KEY_NOT_FOUND));
		else if (keyCouples.size() != 1 && selectingFunction != null) {
			try {
				selectedNo = selectingFunction.selectKey(keyCouples);

			} catch (Exception e) {
				selectedNo = 0;
				e.printStackTrace();
			}
		}
		return keyCouples.get(selectedNo);
	}

	public KeyStore getKeyStore() {
		return keyStore;
	}
	
	public void save(CryptoFile outputFile, char[] pass) throws GbayCryptoException{
		
		try {
			keyStore.store(outputFile.getOutPutStream(), pass);
		} catch (KeyStoreException e) {
			throw new GbayCryptoException(e);
		} catch (NoSuchAlgorithmException e) {
		throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_ALGORITHM));
		} catch (CertificateException e) {
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT));
		} catch (IOException e) {
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.FILE_IO_ERROR));
		} catch (GbayCryptoException e) {
			throw e;
		}
	}
	
	

}
