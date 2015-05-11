package tools.pki.gbay.crypto.provider;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
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
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import tools.pki.gbay.configuration.PropertyFileConfiguration;
import tools.pki.gbay.configuration.SecurityConcepts;
import tools.pki.gbay.configuration.DefualtSignatureSetting;
import tools.pki.gbay.crypto.keys.CertificateInterface;
import tools.pki.gbay.crypto.keys.CertificateValiditor;
import tools.pki.gbay.crypto.keys.KeyStorage;
import tools.pki.gbay.crypto.keys.KeyStorage.CoupleKey;
import tools.pki.gbay.crypto.keys.validation.CertificateIssuer;
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
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import com.google.inject.Inject;

public class SoftCert implements CryptoServiceProvider {

	static {
		SecurityConcepts.addProvider();
	}
	Set<CertificateIssuer> caCert;
	X509CRL crl;
	private X509Certificate currentCert;
	private String filePath;



	private tools.pki.gbay.crypto.keys.KeyStorage keyStorage;
	Logger log = Logger.getLogger(SoftCert.class);


	private CMSSignedData signedData;
	private CoupleKey twinceKey;

	@Inject
	private SignatureSettingInterface settings;
	
	
	private final Type type = Type.softCert;

	public SoftCert() {
		super();
		SecurityConcepts.addProvider();
	}

	public SoftCert(KeyStorage keyStorage) {
		this();
		this.keyStorage = keyStorage;
	}


	public SoftCert( KeyStorage keyStorage,
		 SignatureSettingInterface settings) {
		this(keyStorage);
		this.settings = settings;
	}


	/**
	 * Get set of issuers
	 * @return the caCert
	 * @throws GbayCryptoException
	 * @throws IOException
	 */
	public Set<CertificateIssuer> getCaCert() throws GbayCryptoException {
		if (caCert == null) {
		
			log.info("Getting ca cert...");
		//	if (settings.get!=null)
			caCert = settings.getIssuer(this.currentCert);
		}
		return caCert;
	}

	/**
	 * @return the crl
	 */
	public X509CRL getCrl() {
	
		if (crl == null){
			log.info("Getting Crl...");
			crl = settings.getCrl(currentCert);
		}
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
	 * @param caCert
	 *            the caCert to set
	 */
	public void setCaCert(Set<CertificateIssuer> caCert) {
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
	private byte[] sign(java.security.PrivateKey privateKey,
			List<X509Certificate> certificate, byte[] data) throws GbayCryptoException {
		byte[] signedValue = null;
		try {
			SecurityConcepts.addProvider();


			CMSTypedData msg = new CMSProcessableByteArray(data);
//			certList.add(cert);
			Store certs = new JcaCertStore(certificate);
			
			final ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
			if (settings.getTimeInjectionSetiion().isIncludeTime()){
				final Attribute signingAttribute = new Attribute(CMSAttributes.signingTime, new DERSet(new DERUTCTime(settings.getTimeInjectionSetiion().getTimeSetter().GetCurrentTime()))); 
				signedAttributes.add(signingAttribute);
			}
			// Create the signing table
			final AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);
			final DefaultSignedAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributesTable);
			final JcaSimpleSignerInfoGeneratorBuilder builder = new JcaSimpleSignerInfoGeneratorBuilder().setProvider(SecurityConcepts.getProviderName());
			builder.setSignedAttributeGenerator(signedAttributeGenerator); 
			


			
			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

			for (int i = 0; i < certificate.size(); i++) {
				final SignerInfoGenerator signerGenerator = builder.build(settings.getHashingAlgorythm(), privateKey, certificate.get(i));

				gen.addSignerInfoGenerator(signerGenerator);
				gen.addCertificates(certs);

//				gen.addSignerInfoGenerator(new CMSSignedDataGenerator().build(settings.getHashingAlgorythm(), privateKey,certificate.get(i)));
	//			gen.addCertificates(certs);
			}

			

			// CMSSignedData sigData = gen.generate(msg, false);
			// this is attached
/*			CMSSignedData sigData = gen.generate(msg, true);


			byte[] signedContent = Base64.encode((byte[]) sigData
					.getSignedContent().getContent());

			
			
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
			*/
			signedData = gen.generate(msg, settings.isEncapsulate());
			signedValue = signedData.getEncoded();

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
			throw new GbayCryptoException(GlobalErrorCode.FILE_IO_ERROR);
		} catch (CertificateEncodingException e) {
			
			throw new GbayCryptoException(GlobalErrorCode.CERT_INVALID_FORMAT);
		} catch (OperatorCreationException e) {
			throw new GbayCryptoException(GlobalErrorCode.TXN_FAIL,e.getMessage());
		}
		catch (CMSException e) {
			throw new GbayCryptoException(GlobalErrorCode.SIG_INVALID,e.getMessage());

		}
		if (PropertyFileConfiguration.DEBUG) {
			log.info("Value to be signed: " + new String(data)
					+ PropertyFileConfiguration.newLine + " Signing Result : "
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
			X509Certificate certificate, byte[] data) throws GbayCryptoException {
		List<X509Certificate> cert = new ArrayList<X509Certificate>();
		cert.add(certificate);
		return sign(key, cert, data);
	}

	@Override
	public SignedText sign(PlainText text) throws GbayCryptoException {
		return (SignedText) sign(text,null);
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
				twinceKey.getPublicKey().getCertificate(), text.toByte());
		List<CertificateInterface> signersList = new ArrayList<CertificateInterface>();
		signersList.add(twinceKey.getPublicKey());
		SignedTextInterface st = new SignedText(text.toString(),
				signedPlayLoad, signersList);
		return st;
	}

	/**
     * Checks whether given X.509 certificate is self-signed.
	 * @throws NoSuchProviderException 
     */
    public static boolean isSelfSigned(X509Certificate cert)
            throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
        try {
            // Try to verify certificate signature with its own public key
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
            return true;
        } catch (SignatureException sigEx) {
            // Invalid signature --> not self-signed
            return false;
        } catch (InvalidKeyException keyEx) {
            // Invalid key --> not self-signed
            return false;
        }
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
			if (settings.isEncapsulate()) {
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
				try {
					if (isSelfSigned(currentCert))
						throw new GbayCryptoException(GlobalErrorCode.CERT_IS_SELF_SIGNED);
				} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
					throw new GbayCryptoException(GlobalErrorCode.CERT_INVALID_FORMAT,e.getMessage());
				}
				
				caCert = getCaCert();
				if (caCert == null){
					throw new GbayCryptoException(GlobalErrorCode.CERT_ISSUER_NOT_SET);
				}
				log.debug("ca"+caCert);
				log.info("Checking for revokation...");
				obj.setRevoked(isRevoked());
				log.info("Extracting public key for verification...");
				CertificateValiditor mykey = new CertificateValiditor(currentCert);
				containedkeys.add(mykey);
				if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
						.setProvider(SecurityConcepts.getProviderName()).build(
								currentCert))) {

					log.info(PropertyFileConfiguration.newLine + "Verified");
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
			obj.setValidated(false);
		} catch (CertificateExpiredException e) {
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
		getCrl();
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




}
