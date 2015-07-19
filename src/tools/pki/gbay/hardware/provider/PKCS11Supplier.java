/**
 *	GBay Hardware Devices - a token and smart card management solution (library)
 *	Copyright (c) 2014 Araz Farhang - www.pki.tools
 *
 *	

 *	
 *	This API is intended to be used by other aegis applications
 *
 *	This program is distributed in the hope that it will be useful. *

 *
 */
/*
 * $Header: /cvsroot/GBay Hardware Devices/GBay Hardware Devices/src/java/core/it/trento/comune/GBay Hardware Devices/examples/PKCS11Supplier.java,v 1.12 2005/09/09 04:56:05 resoli Exp $
 * $Revision: 1.12 $
 * $Date: 2005/09/09 04:56:05 $
 */
package tools.pki.gbay.hardware.provider;

import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import tools.pki.gbay.configuration.SecurityConcepts;
import tools.pki.gbay.crypto.texts.BasicText;
import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.CryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;
import tools.pki.gbay.hardware.cms.ManualCMSGenerator;
import tools.pki.gbay.hardware.cms.ManualSignerInfoGenerator;
import tools.pki.gbay.hardware.pcsc.CardInfo;
import tools.pki.gbay.hardware.pcsc.PCSCHelper;
import tools.pki.gbay.hardware.pkcs11.PKCS11Errors;
import tools.pki.gbay.interfaces.DeviceFinderInterface;
import tools.pki.gbay.interfaces.RecursiveSignerInterface;
import tools.pki.gbay.interfaces.SignatureSettingInterface;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.util.encoders.Base64;

import com.google.inject.Inject;


/**
 * A class to provide cryptography functionalities for all pkcs11 devices
 * <p>
 * Multiple signatures are permitted, each with different token types; the
 * generated CMS message keeps signers informations at the same level This
 * "combined signatures" are like me and bahrain signing a document together, A
 * hierarchical type of multiple signatures, We have ("CounterSignature", OID:
 * 1.2.840.113549.1.9.6) also which is not supported yet
 * <p>
 * <b>N.B. note that in this class signature verification only ensures signed
 * data integrity; a complete verification to ensure non-repudiation requires
 * checking the full certification path including the CA root certificate, and
 * CRL verification on the CA side. which can be found in AUTH service and in
 * ACM</b>
 * 
 * @author Araz Farhang
 */
public class PKCS11Supplier {
	static class CONSTANTS {

		public static String MD5_DIGEST_ALGORYTHM = "1.2.840.113549.2.5";
		public static String RSA_ENC_ALGORYTHM = "1.2.840.113549.1.1.1";
		public static String SHA1_DIGEST_ALGORYTHM = "1.3.14.3.2.26";
	}

	
	@Inject
	private SignatureSettingInterface settings;
	
	/**
	 * @return settings used for signings
	 */
	public SignatureSettingInterface getSettings() {
		return settings;
	}

	RecursiveSignerInterface addmoreSignature;
	DeviceFinderInterface cardSelectingFunction;

	Logger log = Logger.getLogger(PKCS11Supplier.class);
	private static int WRAP_AFTER = 16;

	List<CardInfo> conectedCardsList = new ArrayList<CardInfo>();

	// KeyPair dsaSignKP;

	// X509Certificate dsaSignCert;

	// KeyPair dsaOrigKP;

	// X509Certificate dsaOrigCert;

	// String signDN;
	// KeyPair signKP;
	// X509Certificate signCert;
	// String origDN;
	// KeyPair origKP;
	// X509Certificate origCert;
	// String reciDN;
	// KeyPair reciKP;
	X509Certificate reciCert;

	int selectedSlot;

	ArrayList<X509Certificate> signerCertsList = new ArrayList<X509Certificate>();

	// private static String PROPERTIES_FILE = "clitest.properties";

	PKCS11SupplierData variables = new PKCS11SupplierData(null, false, null,
			false, null, null, null);

	/**
	 * Load the provider and auto detect the connected card
	 * @param pin
	 */
	public PKCS11Supplier(String pin) {
		super();
		initialise();
		this.variables.pin = pin;

	}

	/**
	 * @param cryptokiLib
	 * @param pin 
	 * @param cardSelectorListener 
	 * @param addExtraSignatureListener 
	 */
	public PKCS11Supplier(String cryptokiLib, String pin,DeviceFinderInterface cardSelectorListener,RecursiveSignerInterface addExtraSignatureListener) {
		this(pin);
		this.addmoreSignature = addExtraSignatureListener;
		this.cardSelectingFunction = cardSelectorListener;
	
		if (cryptokiLib != null) {
			this.variables.cryptokiLib = cryptokiLib;
			this.variables.forcingCryptoki = true;
			log.debug("Forcing a cryptoki"+cryptokiLib);
		}
	}

	private byte[] applyDigest(String digestAlg, byte[] bytes)
			throws NoSuchAlgorithmException {

		log.info("Applying digest algorithm...");
		MessageDigest md = MessageDigest.getInstance(digestAlg);
		md.update(bytes);

		return md.digest();
	}

	private byte[] applyPkcs1Padding(int resultLength, byte[] srcBytes) {

		int paddingLength = resultLength - srcBytes.length;

		byte[] dstBytes = new byte[resultLength];

		dstBytes[0] = 0x00;
		dstBytes[1] = 0x01;
		for (int i = 2; i < (paddingLength - 1); i++) {
			dstBytes[i] = (byte) 0xFF;
		}
		dstBytes[paddingLength - 1] = 0x00;
		for (int i = 0; i < srcBytes.length; i++) {
			dstBytes[paddingLength + i] = srcBytes[i];
		}
		return dstBytes;
	}

	/**
	 * This triggers the PCSC wrapper stuff; a {@link PCSCHelper}class is used
	 * to detect reader and token presence, trying also to provide a candidate
	 * PKCS#11 cryptoki for it.
	 * <b>note</b> if you set {@link PKCS11Supplier#cardSelectingFunction} it will be called upon detection of card
	 * @param candidateCards list of cards that we are going to search in it
	 * @return true if a token with corresponding candidate cryptoki was
	 *         detected.
	 * @throws CryptoException
	 *             NO_TOKEN_DETECTED if can't find any smart card
	 */
	public List<CardInfo> detectCardAndCriptoki(HashSet<String> candidateCards) throws CryptoException {
		CardInfo ci = null;

//		while (candidateCards.)
	for(String s : candidateCards){
		try {
			PKCS11Manager.getInstance(s);
		} catch (IOException | TokenException e) {
			e.printStackTrace();
		}
		
		
	}
		boolean cardPresent = false;
		log.info("\n\n========= DETECTING CARD ===========");
		selectedSlot = 0;

		PCSCHelper pcsc = new PCSCHelper(true);

		 List<CardInfo> cards = pcsc.findCards();
	//	conectedCardsList = pcsc.findCards();
		cardPresent = !conectedCardsList.isEmpty();

		if (!isForcingCryptoki()) {
			if (cardPresent) {
				try {
					log.info("A card is present, we are trying to get it worked...");

					if (cards != null && cards.size()>1)
						selectedSlot = cardSelectingFunction.selectCard(conectedCardsList);

				} catch (Exception e) {
					log.error(e);
				}
				log.debug("Selected slot is: "+selectedSlot);
				ci = conectedCardsList.get(selectedSlot);
				log.info("\n\nWe will use card: '"
						+ ci.getProperty("description") + "' with criptoki '"
						+ ci.getProperty("lib") + "'");
				log.info(ci.getProperty("lib"));

				setCryptokiLib(ci.getProperty("lib"));
			} else{
				log.info("Sorry, no card detected!");
				throw new CryptoException(new CryptoError(GlobalErrorCode.TOKEN_NOT_INSIDE));
			}
		} else 
			log.info("\n\nFor signing we are forcing use of cryptoki: '"
							+ getCryptokiLib() + "'");

		return (cards);
		
	}
	
	/**
	 * This triggers the PCSC wrapper stuff; a {@link PCSCHelper}class is used
	 * to detect reader and token presence, trying also to provide a candidate
	 * PKCS#11 cryptoki for it.
	 * <b>note</b> if you set {@link PKCS11Supplier#cardSelectingFunction} it will be called upon detection of card
	 * @return true if a token with corresponding candidate cryptoki was
	 *         detected.
	 * @throws IOException
	 * @throws CryptoException
	 *             NO_TOKEN_DETECTED if can't find any smart card
	 */
	public boolean detectCardAndCriptoki() throws CryptoException {
		CardInfo ci = null;

		boolean cardPresent = false;
		log.info("\n\n========= DETECTING CARD ===========");
		selectedSlot = 0;


		

		if (!isForcingCryptoki()) {
			PCSCHelper pcsc = new PCSCHelper(true);

			// List<CardInfo> cards = pcsc.findCards();
			conectedCardsList = pcsc.findCards();
			cardPresent = !conectedCardsList.isEmpty();

			if (cardPresent) {
				try {

					if (cardSelectingFunction != null)
						selectedSlot = cardSelectingFunction.selectCard(conectedCardsList);

				} catch (Exception e) {
					e.printStackTrace();
				}
				ci = conectedCardsList.get(selectedSlot);
				log.info("\n\nWe will use card: '"
						+ ci.getProperty("description") + "' with criptoki '"
						+ ci.getProperty("lib") + "'");
				log.info(ci.getProperty("lib"));

				setCryptokiLib(ci.getProperty("lib"));
			} else{
				log.info("Sorry, no card detected!");
				throw new CryptoException(new CryptoError(GlobalErrorCode.TOKEN_NOT_DETECTED));
			}
		} else 
			log.info("\n\nFor signing we are forcing use of cryptoki: '"
							+ getCryptokiLib() + "'");

		return (getCryptokiLib() != null);
		
	}

	private byte[] encapsulateInDigestInfo(String digestAlg, byte[] digestBytes)
			throws IOException {

		//byte[] bcDigestInfoBytes = null;
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		DEROutputStream dOut = new DEROutputStream(bOut);

		ASN1ObjectIdentifier digestObjId = new ASN1ObjectIdentifier(digestAlg);
		AlgorithmIdentifier algId = new AlgorithmIdentifier(digestObjId, null);
		DigestInfo dInfo = new DigestInfo(algId, digestBytes);

		dOut.writeObject(dInfo);
		return bOut.toByteArray();

	}


	/**
	 * The cryptoki library currently used, as set in
	 * {@link #detectCardAndCriptoki()}method.
	 * 
	 * @return the cryptoki native library to use to access the current PKCS#11
	 *         token.
	 */

	public String getCryptokiLib() {
		return variables.cryptokiLib;
	}

	/**
	 * @return the digestionAlgorithm
	 */
	public String getDigestAlg() {
		return variables.digestionAlgorithm;
	}

	/**
	 * @return the encAlg
	 */
	public String getEncAlg() {
		return variables.encryptionAlgorithm;
	}

	/**
	 * @return the filePath
	 */
	public String getOutputFilePath() {
		return variables.filePath;
	}

	/**
	 * @return the pin
	 */
	public String getPin() {
		return variables.pin;
	}

	/**
	 * @return the plainText
	 */
	public String getPlainText() {
		return variables.plainText;
	}

	/**
	 * Implements a single signature, returning the
	 * {@link ManualSignerInfoGenerator}that encapsulates all signer
	 * informations.
	 * 
	 * 
	 * @param msg
	 *            the content to sign
	 * @param certList
	 *            the list which the signer certificate is to be added to.
	 * @return the <code>ManualSignerInfoGenerator</code> containing all signer
	 *         informations.
	 * @throws CryptoException 
	 */
	ManualSignerInfoGenerator getSignerInfoGenerator(CMSProcessable msg,
			String digestAlg, String encryptionAlg, boolean digestOnToken,
			ArrayList<X509Certificate> certList) throws CryptoException {

		ManualSignerInfoGenerator signerGenerator = new ManualSignerInfoGenerator(
				digestAlg, encryptionAlg);

		try {
			log.info("Calculating bytes to sign ...");

			byte[] bytesToSign = signerGenerator.getBytesToSign(
					PKCSObjectIdentifiers.data, msg,
					SecurityConcepts.getProviderName());
			byte[] rawDigest = null;
			byte[] dInfoBytes = null;
			byte[] paddedBytes = null;

			if (!digestOnToken) {

				rawDigest = applyDigest(digestAlg, bytesToSign);

				log.info("Raw digest bytes:\n" + BasicText.toHexadecimalString(rawDigest, " ", WRAP_AFTER));

				log.info("Encapsulating in a DigestInfo...");

				dInfoBytes = encapsulateInDigestInfo(digestAlg, rawDigest);

				log.info("DigestInfo bytes:\n"
						+ BasicText.toHexadecimalString(dInfoBytes, " ", WRAP_AFTER));

				log.info("Adding Pkcs1 padding...");

				paddedBytes = applyPkcs1Padding(128, dInfoBytes);

				log.info("Padded DigestInfo bytes:\n"
						+ BasicText.toHexadecimalString(paddedBytes, " ", WRAP_AFTER));

			}

			byte[] signedBytes = null;
			byte[] certBytes = null;
			log.debug(SecurityConcepts.StarLine+"Encrypting with pkcs11 token");

			long mechanism = -1L;
			if (CMSSignedDataGenerator.ENCRYPTION_RSA.equals(encryptionAlg))
				if (digestOnToken) {
					if (CMSSignedDataGenerator.DIGEST_MD5.equals(digestAlg))
						mechanism = PKCS11Constants.CKM_MD5_RSA_PKCS;
					else if (CMSSignedDataGenerator.DIGEST_SHA1
							.equals(digestAlg))
						mechanism = PKCS11Constants.CKM_SHA1_RSA_PKCS;
				} else
					mechanism = PKCS11Constants.CKM_RSA_PKCS;

			if (mechanism != -1L) {
			
				PKCS11Manager signAgent = PKCS11Manager.getInstance((getCryptokiLib()));
				log.debug("Using "+signAgent.getCryptokiLibrary()+" for " + mechanism + " mechanism");
				log.info("Finding a token supporting required mechanism and "
								+ "containing a suitable" + "certificate...");

				long t = signAgent.findSuitableToken(mechanism);
				// if suitable token found
				if (t != -1L) {
					signAgent.setMechanism(mechanism);
					signAgent.setTokenHandle(t);
					try{
					signAgent.openSession(variables.pin.toCharArray(),false);
					}
					catch  (PKCS11Exception e){
					log.error(e.getMessage());
					 if	(((PKCS11Exception)e).getErrorCode() != PKCS11Constants.CKR_USER_ALREADY_LOGGED_IN)
						 throw	PKCS11Errors.getCryptoError(((PKCS11Exception)e));
					}
					//}*/
				//	}

					/*
					 * sign using the first key found on token
					 * 
					 * long privateKeyHandle = signAgent.findSignatureKey();
					 * 
					 * if(privateKeyHandle > 0){ signedBytes =
					 * signAgent.signDataSinglePart(privateKeyHandle, digest);
					 * long certHandle =
					 * signAgent.findCertificateFromSignatureKeyHandle
					 * (privateKeyHandle); certBytes =
					 * signAgent.getDEREncodedCertificate(certHandle);
					 * 
					 * }else log.info("\nNo private key found on
					 * token!");
					 */

					// trying a legal value signature finding suitable objects
					// on
					// token
					long certHandle = signAgent
							.findCertificateWithNonRepudiationCritical();
					long privateKeyHandle = signAgent
							.findSignatureKeyFromCertificateHandle(certHandle);

					if (privateKeyHandle > 0) {
						if (!digestOnToken) {
							// Here we could provide padded bytes or DigestInfo
							// bytes;
							// but with padded bytes and Infocamere CNS
							// signDataSinglePart fails! (CKR_FUNCTION_FAILED).
							signedBytes = signAgent.signDataSinglePart(
									privateKeyHandle, dInfoBytes);
						} else
							/*
							 * signedBytes = signAgent.signDataMultiplePart(
							 * privateKeyHandle, new ByteArrayInputStream(
							 * bytesToSign));
							 */
							signedBytes = signAgent.signDataSinglePart(
									privateKeyHandle, bytesToSign);

						certBytes = signAgent
								.getDEREncodedCertificate(certHandle);
					} else
					{
						System.out
										.println("\nNo suitable private key and certificate on token!");

					signAgent.closeSession();
					log.info("Sign session Closed.");

					signAgent.libFinalize();
					log.info("Criptoki library finalized.");
					throw new CryptoException(new CryptoError(
							GlobalErrorCode.KEY_NOT_FOUND));
					}
				}// suitable token found

			} else
				log.info("Mechanism currently not supported");

			if ((certBytes != null) && (signedBytes != null)) {
				log.info("======== Encryption completed =========");
				log.info("\nBytes:\n"
						+ BasicText.toHexadecimalString(bytesToSign, " ", WRAP_AFTER));

				if (dInfoBytes != null)
					log.info("DigestInfo bytes:\n"
							+ BasicText.toHexadecimalString(dInfoBytes, " ", WRAP_AFTER));

				log.info("Encryption result:\n"
						+ BasicText.toHexadecimalString(signedBytes, " ", WRAP_AFTER) + "\n");

				// get Certificate
				java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
						.getInstance("X.509");
				java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(
						certBytes);
				java.security.cert.X509Certificate javaCert = (java.security.cert.X509Certificate) cf
						.generateCertificate(bais);

				// Decription
				PublicKey pubKey = javaCert.getPublicKey();

				try {
					log.info("Decrypting...");

					Cipher c = Cipher.getInstance("RSA/ECB/PKCS1PADDING", SecurityConcepts.getProviderName());

					c.init(Cipher.DECRYPT_MODE, pubKey);

					byte[] decBytes = c.doFinal(signedBytes);

					log.debug("Decrypted bytes (should match DigestInfo bytes):\n"
									+ BasicText.toHexadecimalString(decBytes, " ", WRAP_AFTER));

				
				}catch (NoSuchAlgorithmException e1) {
					log.error("Signer info generation failed , We couldn't make CMS"+e1);
					
					throw new CryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_ALGORITHM));
				} catch (NoSuchPaddingException e1) {
					log.error("Signer info generation failed , We couldn't make CMS"+e1);

					throw new CryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_PADDING));
				} catch (InvalidKeyException e2) {
					log.error("Signer info generation failed , We couldn't make CMS"+e2);

					throw new CryptoException(new CryptoError(GlobalErrorCode.KEY_INVALID));
				} catch (IllegalStateException e) {
					log.error("Signer info generation failed , We couldn't make CMS"+e);
					throw new CryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT));
				} catch (IllegalBlockSizeException e) {
					log.error("Signer info generation failed , We couldn't make CMS"+e);
					throw new CryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT));
				} catch (BadPaddingException e) {
					log.error("Signer info generation failed , We couldn't make CMS"+e);
					throw new CryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_PADDING));
				} catch (NoSuchProviderException e) {
					log.error("Signer info generation failed , We couldn't make CMS"+e);
					throw new CryptoException(new CryptoError(GlobalErrorCode.KEY_PROVIDER_NOT_FOUND));
				}

				signerGenerator.setCertificate(javaCert);
				signerGenerator.setSignedBytes(signedBytes);

				certList.add(javaCert);

			} else
				signerGenerator = null;
		}catch(CryptoException e){
			throw e;
		}
		catch (TokenException e) {
/*			if (e instanceof PKCS11Exception){
				log.error(e.getMessage());
			 if	(((PKCS11Exception)e).getErrorCode() != PKCS11Constants.CKR_USER_ALREADY_LOGGED_IN)
			
				 throw	PKCS11Errors.getCryptoError(((PKCS11Exception)e));
			//}*/
		//	}
			//else
			if (e instanceof TokenException){
				log.debug(((TokenException)e).getMessage());
				 throw new CryptoException(new CryptoError(GlobalErrorCode.PIN_INCORRECT));				
			}
			else{
				
				 throw new CryptoException(e);				
					
			}
		} catch (Throwable e) {
			
			log.error(e);
			 throw new CryptoException(new CryptoError(GlobalErrorCode.TOKEN_ERR_LOAD_LIBRARY));
				
		}

		return signerGenerator;
	}

	private void initialise() {

		System.loadLibrary("ocfpcsc1");

		if (this.variables.digestionAlgorithm == null)
			this.variables.digestionAlgorithm = CMSSignedDataGenerator.DIGEST_SHA1;

		if (variables.encryptionAlgorithm == null)
			this.variables.encryptionAlgorithm = CMSSignedDataGenerator.ENCRYPTION_RSA;

	}


	/**
	 * Check if we are just checking a specific driver and do operations on that
	 * @return true if there is Cryptoki library that we are forced to use
	 */
	public boolean isForcingCryptoki() {
		return variables.forcingCryptoki;
	}

	/**
	 * @return the makeDigestOnToken
	 */
	public boolean isMakeDigestOnToken() {
		return variables.makeDigestOnToken;
	}

	/**
	 * Sets th cryptoki library to use to access the current PKCS#11 token; This
	 * method is used internally in {@link #detectCardAndCriptoki()}method.
	 * 
	 * @param lib
	 */
	private void setCryptokiLib(String lib) {
		this.variables.cryptokiLib = lib;
	}

	/**
	 * @param digestAlg  the digestionAlgorithm to set
	 */
	public void setDigestAlg(String digestAlg) {
		this.variables.digestionAlgorithm = digestAlg;
	}

	/**
	 * @param encAlg
	 *            the encAlg to set
	 */
	public void setEncAlg(String encAlg) {
		this.variables.encryptionAlgorithm = encAlg;
	}



	/**
	 * @param forcingCryptoki
	 *            the forcingCryptoki to set
	 */
	public void setForcingCryptoki(boolean forcingCryptoki) {
		this.variables.forcingCryptoki = forcingCryptoki;
	}

	/**
	 * @param makeDigestOnToken
	 *            the makeDigestOnToken to set
	 */
	public void setMakeDigestOnToken(boolean makeDigestOnToken) {
		this.variables.makeDigestOnToken = makeDigestOnToken;
	}

	/**
	 * @param filePath
	 *            the filePath to set
	 */
	public void setOutputFilePath(String filePath) {
	log.info("Setting output PATH");
		this.variables.filePath = filePath;
	}

	/**
	 * @param pin
	 *            the pin to set
	 */
	public void setPin(String pin) {
		this.variables.pin = pin;
	}

	/**
	 * @param plainText
	 *            the plainText to set
	 */
	public void setPlainText(String plainText) {
		this.variables.plainText = plainText;
	}

	

	/**
	 * Sign (possibly multiple) digital signatures using PKCS#11 tokens. After
	 * correct verification of all signatures, the CMS signed message is saved
	 * on the filesystem under the users's home directory.
	 * @throws CryptoException 
	 * 
	 */
	public void signText() throws CryptoException {

		if (variables.plainText != null){

		try {
			boolean moreThan1Sign = false;
			boolean addAnotherSign = true;
			if (addmoreSignature != null)
				moreThan1Sign = true;

			log.debug("========= CMS (PKCS7) Signed message  ========\n\n");

			log.debug("Original Text :" + variables.plainText + "\n As exadecimal string:\t\t"+BasicText.toHexadecimalString(variables.plainText.getBytes(),
					" ", WRAP_AFTER));
		
			CMSProcessable msg = new CMSProcessableByteArray(
					variables.plainText.getBytes());
			ManualCMSGenerator gen = new ManualCMSGenerator();
			// ArrayList<X509Certificate> certList = new
			// ArrayList<X509Certificate>();

			ManualSignerInfoGenerator sig = null;

		int i = 0;
			while (addAnotherSign) {
				if (detectCardAndCriptoki()) {
					i++;
					log.info("========================");
					log.info("ADDING SIGNATURE " + i);
					log.info("Starting signing process.");
					// Applying SHA1 digest with RSA encryption.
					sig = getSignerInfoGenerator(msg,
							this.variables.digestionAlgorithm,
							this.variables.encryptionAlgorithm,
							this.variables.makeDigestOnToken, // digest
							// on
							// token?
							signerCertsList);

					if (sig != null)
						gen.addSignerInf(sig);
				}// if card detected
				if (moreThan1Sign && addmoreSignature !=null) {
					try {
						addAnotherSign = addmoreSignature.addMore(i);
					} catch (Exception e) {
						e.printStackTrace();
					}
				} else {
					addAnotherSign = false;
				}
			}

			if (signerCertsList.size() != 0) {

				// To pass the certificates to the generator that encapsulates
				// them
				CertStore store = CertStore.getInstance("Collection",
						new CollectionCertStoreParameters(signerCertsList),
						SecurityConcepts.getProviderName());

				log.info("Adding certificates ... ");
				gen.addCertificatesAndCRLs(store);

				// Generate CMS.
				log.info("Generating CMSSignedData ");
				CMSSignedData s = gen.generate(msg, settings.isEncapsulate());
				variables.signingResult = s;

				log.info("Signed:" + new String( Base64.encode(s.getEncoded())));
				log.info("\nStarting CMSSignedData verification ... ");
				
		/*
				Store certs = s.getCertificates();

				SignerInformationStore signers = s.getSignerInfos();
				Collection c = signers.getSigners();

				log.info(c.size() + " signers found.");

				/*******************************************************************/
				// TODO : need to decide what will happen if a signing is not verified
		/*		Iterator it = c.iterator();
				int verified = 0;
				int signerCount = 0;

				while (it.hasNext()) {
					SignerInformation signer = (SignerInformation) it.next();
					Collection certCollection = certs.getMatches(signer
							.getSID());

					
					// if ()
					Iterator certIt = certCollection.iterator();
					X509Certificate cert = new JcaX509CertificateConverter()
							.getCertificate((X509CertificateHolder) certIt
									.next());
				//	variables.certs.add(new tools.pki.gbay.crypto.keys.PublicKey(cert));
					signerCount++;
					// X509Certificate certReal = (X509Certificate)
					// certCollection
					// .toArray()[0];
					log.info("Verifiying signature from:\n"
							+ cert.getSubjectDN());
					log.info("Certificate : " +PropertyFileConfiguration.StarLine + PropertyFileConfiguration.newLine+cert + PropertyFileConfiguration.newLine + PropertyFileConfiguration.StarLine);

		//			if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
			//				.setProvider("BC").build(cert))) {
			//			verified++;
			//		} else {
				//		log.warn("Certificate: "+cert.getSubjectDN() +PropertyFileConfiguration.StarLine + PropertyFileConfiguration.newLine + " could not be verified");
				//	}
				}

		//		if (signerCount != verified){
	//				log.warn("We signed using "+signerCount + " but just " + verified +"was properly signed and verified");
//				}*/
				if (variables.filePath != null) {
					writeToFile(s, variables.filePath);
					log.info("Signed text has been saved into "+ variables.filePath);
				}
				log.info("Sigining was done successfully");
			}
		}
		catch(CryptoException e){
			throw e;
		
		} catch (IOException e) {
			throw new CryptoException(new CryptoError(GlobalErrorCode.FILE_NOT_FOUND,variables.filePath));
		} catch (InvalidAlgorithmParameterException e) {
			log.error(e);
			throw new CryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_ALGORITHM));
		} catch (NoSuchAlgorithmException e) {
			log.error(e);
			throw new CryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_ALGORITHM));
		} catch (NoSuchProviderException e) {
			log.error(e);
			throw new CryptoException(new CryptoError(GlobalErrorCode.KEY_PROVIDER_NOT_FOUND));
		} catch (CertStoreException e) {
			log.error(e);
			throw new CryptoException(new CryptoError(GlobalErrorCode.KEY_INVALID));
		} catch (CMSException e) {
			log.error(e);
			throw new CryptoException(new CryptoError(GlobalErrorCode.ENTITY_INCORRECT_FORMAT));
		}
		
		}
		else  {
			log.error("You hav not provide original text");
			throw new CryptoException(new CryptoError(GlobalErrorCode.REQ_PARAMETER_FAILED));	
		}
	}

	private void writeToFile(CMSSignedData s, String filePath)
			throws FileNotFoundException, IOException {
		FileOutputStream fos = new FileOutputStream(filePath);
		fos.write(s.getEncoded());
		fos.flush();
		fos.close();
	}
}