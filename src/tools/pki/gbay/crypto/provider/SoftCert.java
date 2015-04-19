package tools.pki.gbay.crypto.provider;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import tools.pki.gbay.configuration.Configuration;
import tools.pki.gbay.configuration.SecurityConcepts;
import tools.pki.gbay.crypto.keys.CertificateInterface;
import tools.pki.gbay.crypto.keys.CertificateValiditor;
import tools.pki.gbay.crypto.keys.KeyStorage;
import tools.pki.gbay.crypto.keys.KeyStorage.CoupleKey;
import tools.pki.gbay.crypto.keys.validation.CertificateIssuer;
import tools.pki.gbay.crypto.keys.validation.CrlCheckParameters;
import tools.pki.gbay.crypto.keys.validation.IssuerPropertyFile;
import tools.pki.gbay.crypto.texts.Base64;
import tools.pki.gbay.crypto.texts.EncryptedText;
import tools.pki.gbay.crypto.texts.PlainText;
import tools.pki.gbay.crypto.texts.SignedText;
import tools.pki.gbay.crypto.texts.SignedTextInterface;
import tools.pki.gbay.crypto.texts.VerifiedText;
import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.GbayCryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;

import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class SoftCert implements CryptoServiceProvider {

	static {
		SecurityConcepts.addProvider();
	}
	CertificateIssuer caCert;
	X509CRL crl;

	private X509Certificate currentCert;

	private String filePath;

	private CaFinderInterface issuerCaller;

	private boolean isAttached;

	private IssuerPropertyFile issuerPropertyFile;

	private CrlFinderInterface getCrlCaller;

	private tools.pki.gbay.crypto.keys.KeyStorage keyStorage;
	Logger log = Logger.getLogger(SoftCert.class);

	/**
	 * 
	 * @param privateKey
	 * @param certificate
	 * @param data
	 * @param encapsulate
	 *            if true it will add the original data into the signed text
	 * @return
	 */
	private KeySelectionInterface selectKeyFunction;
	private CMSSignedData signedData;
	private CoupleKey twinceKey;

	private final Type type = Type.softCert;

	public SoftCert() {
		SecurityConcepts.addProvider();
	}

	public SoftCert(KeyStorage keyStorage) {
		super();
		this.keyStorage = keyStorage;
	}

	public SoftCert(KeyStorage keyStorage,
			java.util.Properties issuerPropertiesFile) {
		super();
		this.keyStorage = keyStorage;

	}

	public SoftCert(CaFinderInterface issuerfinder, KeyStorage keyStorage,
			KeySelectionInterface selectKeyFunction) {
		super();
		this.issuerCaller = issuerfinder;
		this.keyStorage = keyStorage;
		this.selectKeyFunction = selectKeyFunction;
	}


	/**
	 * @return the caCert
	 * @throws GbayCryptoException
	 * @throws IOException
	 */
	public CertificateIssuer getCaCert() throws GbayCryptoException {
		if (caCert == null) {
			log.debug("CA Cert is null...");
			if (issuerCaller == null) {
				log.debug("Issuer finder interface is null we constract using our own Issuer Property file");
				try {
					issuerCaller = new ScanCaFinder(null);
				} catch (IOException e) {
					log.debug("Issuer property file could not be read");
					throw new GbayCryptoException(GlobalErrorCode.FILE_IO_ERROR);
				}
			}
			log.info("Getting ca cert...");
			caCert = issuerCaller.getIssuer(this.currentCert);
		}
		return caCert;
	}

	/**
	 * @return the crl
	 */
	public X509CRL getCrl() {
		return crl;
	}

	/**
	 * @return the currentCert
	 */
	public X509Certificate getCurrentCert() {
		return currentCert;
	}

	/**
	 * @return the filePath
	 */
	public String getFilePath() {
		return filePath;
	}

	/**
	 * @return the keyStorage
	 */
	public tools.pki.gbay.crypto.keys.KeyStorage getKeyStorage() {
		return keyStorage;
	}

	@Override
	public CMSSignedData getSignedData() {
		return signedData;
	}

	/**
	 * @return the twinceKey
	 */
	public CoupleKey getTwinceKey() {
		return twinceKey;
	}

	/**
	 * @return the type
	 */
	public Type getType() {
		return type;
	}

	@Override
	public void includeOriginalText(boolean isAttached) {
		this.isAttached = isAttached;
	}

	/**
	 * @return the isAttached
	 */
	public boolean isAttached() {
		return isAttached;
	}

	/**
	 * Check if text is signed by specific user and is verified and validated
	 * 
	 * @param signedText 	Base64 of SignedText
	 * @param OriginalText
	 * @param userCert
	 * @param caCert
	 * @return
	 * @throws GbayCryptoException
	 */
	public boolean isSignedByUser(VerifiedText verificationResult,
			X509Certificate userCert) throws GbayCryptoException {
		return verificationResult.getCertificates().equals(userCert);
	}

	/**
	 * @param isAttached
	 *            the isAttached to set
	 */
	public void setAttached(boolean isAttached) {
		this.isAttached = isAttached;
	}

	/**
	 * @param caCert
	 *            the caCert to set
	 */
	public void setCaCert(CertificateIssuer caCert) {
		this.caCert = caCert;
	}

	/**
	 * @param crl
	 *            the crl to set
	 */
	public void setCrl(X509CRL crl) {
		this.crl = crl;
	}

	/**
	 * @param currentCert
	 *            the currentCert to set
	 */
	public void setCurrentCert(X509Certificate currentCert) {
		this.currentCert = currentCert;
	}

	/**
	 * @param filePath
	 *            the filePath to set
	 */
	public void setFilePath(String filePath) {
		this.filePath = filePath;
	}

	/**
	 * @param keyStorage
	 *            the keyStorage to set
	 */
	public void setKeyPair(tools.pki.gbay.crypto.keys.KeyStorage keyStorage) {
		this.keyStorage = keyStorage;
	}

	/**
	 * @param keyStorage
	 *            the keyStorage to set
	 */
	public void setKeyStorage(
			tools.pki.gbay.crypto.keys.KeyStorage keyStorage) {
		this.keyStorage = keyStorage;
	}

	public void setOutputFilePath(String filePath) {
		log.debug("Setting output file address, results will be available in: "
				+ filePath);
		this.filePath = filePath;
	}

	/**
	 * @param signedData
	 *            the signedData to set
	 */
	public void setSignedData(CMSSignedData signedData) {
		this.signedData = signedData;
	}

	/**
	 * @param twinceKey
	 *            the twinceKey to set
	 */
	public void setTwinceKey(CoupleKey twinceKey) {
		this.twinceKey = twinceKey;
	}

	/***
	 * Sign an array of bytes using a {@link SoftCert}
	 * <p>
	 * it Generates a Signed Data which can be carrying a detached CMS
	 * signature, or have encapsulated data, depending on the value of the
	 * encapsulated parameter.
	 * </p>
	 * 
	 * @param privateKey
	 * @param certificate
	 *            list of java {@link java.security.cert.X509Certificate} that
	 *            will be added as signers
	 * @param data
	 * @param encapsulate
	 *            true if the content should be encapsulated in the signature,
	 *            false otherwise.
	 * @return byte array of signed value
	 * @throws GbayCryptoException 
	 */
	public byte[] sign(java.security.PrivateKey privateKey,
			List<X509Certificate> certificate, byte[] data, boolean encapsulate) throws GbayCryptoException {
		byte[] signedValue = null;
		try {
			SecurityConcepts.addProvider();

			// New BC

			// CMSTypedData msg = new
			// CMSProcessableByteArray("Hello world!".getBytes());

			// Sign

			Signature signature = Signature.getInstance("SHA1WithRSA", "BC");
			signature.initSign(privateKey);
			signature.update(data);

			// List<X509Certificate> certList = new
			// ArrayList<X509Certificate>();
			CMSTypedData msg = new CMSProcessableByteArray(signature.sign());
			// CMSTypedData msg = new CMSProcessableByteArray(data);
			// certList.add(certificate);
			Store certs = new JcaCertStore(certificate);
			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

			ContentSigner sha1Signer = new JcaContentSignerBuilder(
					"SHA1withRSA").setProvider("BC").build(privateKey);
			for (int i = 0; i < certificate.size(); i++) {

				gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
						new JcaDigestCalculatorProviderBuilder().setProvider(
								"BC").build()).build(sha1Signer,
						certificate.get(i)));
				gen.addCertificates(certs);
			}
			signedData = gen.generate(msg, encapsulate);

			// CMSSignedData signedData2 = gen.generate(msg, false );

			/*
			 * SCEJ CMSSignedDataGenerator generator = new
			 * CMSSignedDataGenerator();
			 * 
			 * generator.addSigner(privateKey, certificate,
			 * CMSSignedDataGenerator.DIGEST_SHA1); ArrayList<Certificate> list
			 * = new ArrayList<Certificate>(); list.add(certificate); CertStore
			 * certStore = CertStore.getInstance("Collection", new
			 * CollectionCertStoreParameters(list), "BC");
			 * generator.addCertificatesAndCRLs(certStore); CMSProcessable
			 * content = new CMSProcessableByteArray(data);
			 * 
			 * CMSSignedData signedData = generator.generate(content, false);
			 */
			signedValue = signedData.getEncoded();
			// byte[] signedValue2 = signedData.getEncoded();

			certificate.clear();
			certs = null;
			certificate = null;
			if (filePath != null) {
				try {
					FileOutputStream fos = new FileOutputStream(filePath);
					fos.write(signedData.getEncoded());
					fos.close();
					fos.flush();
				} catch (IOException ex) {
				//	ex.printStackTrace();
					throw new GbayCryptoException(new CryptoError(
							GlobalErrorCode.FILE_IO_ERROR));
				}
			}
		} catch (IOException e ) {
		
		//	e.printStackTrace();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CMSException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (Configuration.DEBUG) {
			log.info("Value to be signed: " + new String(data)
					+ Configuration.newLine + " Signing Result : "
					+ new Base64(signedValue));
		}
		return signedValue;
	}

	/**
	 * Sign using a private key and representative public keys to be added to
	 * the signed text
	 * 
	 * @param key
	 * @param certificate
	 * @param data
	 * @param encapsulate
	 * @return
	 * @throws GbayCryptoException 
	 */
	public byte[] sign(java.security.PrivateKey key,
			X509Certificate certificate, byte[] data, boolean encapsulate) throws GbayCryptoException {
		List<X509Certificate> cert = new ArrayList<X509Certificate>();
		cert.add(certificate);
		return sign(key, cert, data, encapsulate);
	}

	@Override
	public SignedText sign(PlainText text) throws GbayCryptoException {
		return (SignedText) sign(text, selectKeyFunction);
	}

	/**
	 * Use {@link KeyStorage} to sign a text. To sign using this function you
	 * need to set the KeyStorage First
	 * 
	 * @param text
	 * @param selectingFunction
	 * @return
	 * @throws GbayCryptoException
	 */
	public SignedTextInterface sign(PlainText text,
			KeySelectionInterface selectingFunction) throws GbayCryptoException {
		twinceKey = keyStorage.getCoupleKey(selectingFunction);
		byte[] signedPlayLoad = sign(twinceKey.getPrivateKey(),
				twinceKey.getPublicKey().getCertificate(), text.toByte(), false);
		List<CertificateInterface> signersList = new ArrayList<CertificateInterface>();
		signersList.add(twinceKey.getPublicKey());
		SignedTextInterface st = new SignedText(text.toString(),
				signedPlayLoad, signersList);
		return st;
	}

	/***
	 * Verifies a signed text, if the signedText has it's own crl will verifies
	 * over it, if not it verifies over the CRL of SoftCert Object As for
	 * Issuers it will verifys to all issuers inside of signedText and SoftCert,
	 * if the text is signed with even only one trusted issuer it can be
	 * verified
	 * 
	 */
	@Override
	public VerifiedText verify(SignedText text, PlainText originalText)
			throws GbayCryptoException {
		// CertificateIssuer issuer = caCert ;
		// X509CRL crl = this.crl;
		if (text.getTrustedIssuers() != null)
			caCert = text.getTrustedIssuers();
		// if (getIssuerCaller != null)

		// return VerifyAndValidate(text, originalText);
		if (text.getCrl() != null)
			crl = text.getCrl().getCrl();
		return VerifyAndValidate(text, originalText);
	}

	/**
	 * Verify and validate a signed text By defualt we use certrepos and cdp to
	 * get CRL and use property file to find issuer, but it can be customised by
	 * setting the interface The implementer needs to implement a proper
	 * function to provide CertificateIssuer and CRL for validation
	 * 
	 * @param signedText
	 *            Base64 of SignedText
	 * @param OriginalText
	 * @return A text Containing Verification Result
	 * @throws GbayCryptoException
	 */
	@SuppressWarnings("rawtypes")
	private VerifiedText VerifyAndValidate(SignedText signedText,
			PlainText OriginalText) throws GbayCryptoException {
		ArrayList<CertificateValiditor> containedkeys = new ArrayList<CertificateValiditor>();
		VerifiedText obj = new VerifiedText(OriginalText.toString(), signedText);
		if (obj.getCrl() != null)
			crl = obj.getCrl().getCrl();
		boolean isValidated = true;
		boolean isVerified = true;

		try {

			SecurityConcepts.addProvider();

			CMSSignedData cms = null;
			if (isAttached) {
				cms = new CMSSignedData(signedText.getSignedVal());
			} else {
				log.info("Encapsulated, constract with original text : "
						+ new String(OriginalText.toByte()));
				CMSProcessableByteArray dataCMS = new CMSProcessableByteArray(
						OriginalText.toByte());
				log.debug("data cms generated...");
				cms = new CMSSignedData(dataCMS, signedText.getSignedVal());
				log.debug("CMS Generated...");
			}

			Store store = cms.getCertificates();
			log.debug("Extracting certs from CMS...");
			SignerInformationStore signers = cms.getSignerInfos();
			Collection c = signers.getSigners();
			Iterator it = c.iterator();
			log.debug("Singers info extracted...");
			while (it.hasNext()) {
				SignerInformation signer = (SignerInformation) it.next();
				Collection certCollection = store.getMatches(signer.getSID());
				Iterator certIt = certCollection.iterator();
				X509CertificateHolder certHolder = (X509CertificateHolder) certIt
						.next();
				currentCert = new JcaX509CertificateConverter().setProvider(
						SecurityConcepts.getProviderName()).getCertificate(
						certHolder);
				log.debug("Current cert is extracted");
				caCert = getCaCert();
				if (caCert == null){
					throw new GbayCryptoException(GlobalErrorCode.CERT_ISSUER_NOT_SET);
				}
				log.debug("ca"+caCert);
				log.info("Checking for revokation...");
				obj.setRevoked(isRevoked());
				log.info("Extracting public key for verification...");
				CertificateValiditor mykey = new CertificateValiditor(currentCert, caCert, crl);
				containedkeys.add(mykey);
				if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
						.setProvider(SecurityConcepts.getProviderName()).build(
								currentCert))) {

					log.info(Configuration.newLine + "Verified");
					obj.getCertificates().add(mykey);

					if (!mykey.isValidated()) {
						isValidated = false;
						log.info("verified");
					}
				} else {
					isVerified = false;
				}
			}
		} catch (CMSException e1) {
			e1.printStackTrace();
			throw new GbayCryptoException(new CryptoError(
					GlobalErrorCode.SIG_NOT_FOUND));
		} catch (CertificateExpiredException e) {
			obj.setValidated(false);
		} catch (CertificateNotYetValidException e) {
			obj.setValidated(false);
		} catch (OperatorCreationException e) {
			throw new GbayCryptoException(
					new CryptoError(GlobalErrorCode.SIG_INVALID));
		} catch (CertificateException e) {
			throw new GbayCryptoException(new CryptoError(
					GlobalErrorCode.CERT_INVALID_FORMAT));
		} 
		obj.setValidated(isValidated);
		obj.setVerified(isVerified);
		return obj;
	}

	/**
	 * Check if cert is revoked, if you set certrepos URL to null and retry
	 * counts to -1 it will use default values in configuration
	 * 
	 * @param certRepos
	 *            URL address of cert Repos
	 * @param maxRetryRepos
	 *            Maximum retrying of getting CRL from cert repos
	 * @param maxRetryCDP
	 *            Maximum retrying of getting CRL from CDP in cert file
	 * @return
	 * @throws IOException
	 *             CRL is not readable
	 * @throws CertificateException
	 * @throws GbayCryptoException 
	 */
	public boolean isRevoked() throws  GbayCryptoException {
		if (crl == null) {
			if (getCrlCaller != null) {
				crl = getCrlCaller.getCrl(currentCert);
			}
		}
		if (crl != null) {
			log.info("We got CRL for"
					+ new String(crl.getIssuerDN().toString()));
			if (!crl.isRevoked(currentCert)) {
				log.info("Certificate is revoked");
				return true;
			}
		} else {
			log.info("We could not get any CRL to verify the cert using it");
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_CRL_NOT_FOUND));
		}
		return true;
	}

	@Override
	public EncryptedText encrypt(PlainText text) throws GbayCryptoException {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * @return the getIssuerCaller
	 */
	public CaFinderInterface getIssuerFinder() {
		return issuerCaller;
	}

	/**
	 * @param getIssuerCaller
	 *            the getIssuerCaller to set
	 */
	public void setGetIssuerCaller(CaFinderInterface getIssuerCaller) {
		this.issuerCaller = getIssuerCaller;
	}

	/**
	 * @return the selectKeyFunction
	 */
	public KeySelectionInterface getSelectKeyFunction() {
		return selectKeyFunction;
	}

	/**
	 * @param selectKeyFunction
	 *            the selectKeyFunction to set
	 */
	public void setSelectKeyFunction(KeySelectionInterface selectKeyFunction) {
		this.selectKeyFunction = selectKeyFunction;
	}

	/**
	 * @param getCrlCaller
	 *            the getCrlCaller to set
	 */
	public void setGetCrlCaller(CrlFinderInterface getCrlCaller) {
		this.getCrlCaller = getCrlCaller;
	}

	/**
	 * @return the issuerPropertyFile
	 */
	public IssuerPropertyFile getIssuerPropertyFile() {
		return issuerPropertyFile;
	}

	/**
	 * @param issuerPropertyFile
	 *            the issuerPropertyFile to set
	 */
	public void setIssuerPropertyFile(IssuerPropertyFile issuerPropertyFile) {
		this.issuerPropertyFile = issuerPropertyFile;
	}

}
