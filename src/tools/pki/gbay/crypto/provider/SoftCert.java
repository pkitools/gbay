/*
 * GBAy Crypto API
 * Copyright (c) 2014, PKI.Tools All rights reserved.
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
package tools.pki.gbay.crypto.provider;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
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

import tools.pki.gbay.configuration.PropertyFileConfiguration;
import tools.pki.gbay.configuration.SecurityConcepts;
import tools.pki.gbay.crypto.keys.CertificateInterface;
import tools.pki.gbay.crypto.keys.CertificateValiditor;
import tools.pki.gbay.crypto.keys.KeyStorage;
import tools.pki.gbay.crypto.keys.KeyStorage.CoupleKey;
import tools.pki.gbay.crypto.keys.validation.CertificateChain;
import tools.pki.gbay.crypto.texts.Base64;
import tools.pki.gbay.crypto.texts.EncryptedText;
import tools.pki.gbay.crypto.texts.PlainText;
import tools.pki.gbay.crypto.texts.SignedText;
import tools.pki.gbay.crypto.texts.SignedTextInterface;
import tools.pki.gbay.crypto.texts.VerifiedText;
import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.CryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;
import tools.pki.gbay.interfaces.KeySelectionInterface;
import tools.pki.gbay.interfaces.SignatureSettingInterface;

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
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

import com.google.inject.Inject;

/**
 * The Class SoftCert is used for all private keys, public keys and related certificate
 */
public class SoftCert implements CryptoServiceProvider {

	static {
		SecurityConcepts.addProvider();
	}
	
	/** The ca cert. */
	CertificateChain caCert;
	
	/** The crl. */
	X509CRL crl;
	private X509Certificate currentCert;
	private String filePath;

	private tools.pki.gbay.crypto.keys.KeyStorage keyStorage;
	
	/** The log. */
	Logger log = Logger.getLogger(SoftCert.class);

	private CMSSignedData signedData;
	private CoupleKey twinceKey;

	@Inject SignatureSettingInterface settings;

	private final Type type = Type.softCert;

	
	/**
	 * To provide operations for a File
	 */
	public  SoftCert() {
		super();
		SecurityConcepts.addProvider();
		log.debug("Softcert Created");
	}

	/**
	 * The Constructor.
	 * @param ssi settings
	 */
	
	
	@Inject
	public  SoftCert(SignatureSettingInterface ssi) {
		super();
		this.settings = ssi;
		SecurityConcepts.addProvider();
		log.debug("Softcert Created");
	}

	/**
	 * The Constructor.
	 * @param ssi 
	 *
	 * @param keyStorage the key storage
	 */
	@Inject
	public SoftCert(SignatureSettingInterface ssi, KeyStorage keyStorage) {
		this(ssi);
		this.keyStorage = keyStorage;
	}

	/**
	 * The Constructor.
	 *
	 * @param keyStorage the key storage
	 */
	public SoftCert(KeyStorage keyStorage) {

		this.keyStorage = keyStorage;
	}

	/**
	 * Get set of issuers.
	 *
	 * @return the caCert
	 * @throws CryptoException the gbay crypto exception
	 */
	public CertificateChain getCaCert() throws CryptoException {
		if (caCert == null) {

			log.info("Getting ca cert...");
			// if (settings.get!=null)
			caCert = settings.getIssuer(this.currentCert);
		}
		return caCert;
	}

	/**
	 * Gets the crl.
	 *
	 * @return the crl
	 */
	public X509CRL getCrl() {

		if (crl == null) {
			log.info("Getting Crl...");
			crl = settings.getCrl(currentCert);
		}
		return crl;
	}

	/**
	 * Gets the current cert.
	 *
	 * @return the currentCert
	 */
	public X509Certificate getCurrentCert() {
		return currentCert;
	}

	/**
	 * Gets the file path.
	 *
	 * @return the filePath
	 */
	public String getFilePath() {
		return filePath;
	}

	/**
	 * Gets the key storage.
	 *
	 * @return the keyStorage
	 */
	public tools.pki.gbay.crypto.keys.KeyStorage getKeyStorage() {
		return keyStorage;
	}


	/**
	 * @return Signed Data
	 */
	public CMSSignedData getSignedData() {
		return signedData;
	}

	/**
	 * Gets the twince key.
	 *
	 * @return the twinceKey
	 */
	public CoupleKey getTwinceKey() {
		return twinceKey;
	}

	/**
	 * Gets the type.
	 *
	 * @return the type
	 */
	public Type getType() {
		return type;
	}

	/**
	 * Check if text is signed by specific user and is verified and validated.
	 *
	 * @param verificationResult the verification result
	 * @param userCert the user cert
	 * @return true, if checks if is signed by user
	 * @throws CryptoException the gbay crypto exception
	 */
	public boolean isSignedByUser(VerifiedText verificationResult,
			X509Certificate userCert) throws CryptoException {
		return verificationResult.getCertificates().equals(userCert);
	}

	/**
	 * Sets the ca cert.
	 *
	 * @param caCert            the caCert to set
	 */
	public void setCaCert(CertificateChain caCert) {
		this.caCert = caCert;
	}

	/**
	 * Sets the crl.
	 *
	 * @param crl            the crl to set
	 */
	public void setCrl(X509CRL crl) {
		this.crl = crl;
	}

	/**
	 * Sets the current cert.
	 *
	 * @param currentCert            the currentCert to set
	 */
	public void setCurrentCert(X509Certificate currentCert) {
		this.currentCert = currentCert;
	}

	/**
	 * Sets the file path.
	 *
	 * @param filePath            the filePath to set
	 */
	public void setFilePath(String filePath) {
		this.filePath = filePath;
	}

	/**
	 * Sets the key pair.
	 *
	 * @param keyStorage            the keyStorage to set
	 */
	public void setKeyPair(tools.pki.gbay.crypto.keys.KeyStorage keyStorage) {
		this.keyStorage = keyStorage;
	}

	/**
	 * Sets the key storage.
	 *
	 * @param keyStorage            the keyStorage to set
	 */
	public void setKeyStorage(tools.pki.gbay.crypto.keys.KeyStorage keyStorage) {
		this.keyStorage = keyStorage;
	}

	/**
	 * Sets the output file path.
	 *
	 * @param filePath the output file path
	 */
	public void setOutputFilePath(String filePath) {
		log.debug("Setting output file address, results will be available in: "
				+ filePath);
		this.filePath = filePath;
	}

	/**
	 * Sets the signed data.
	 *
	 * @param signedData            the signedData to set
	 */
	public void setSignedData(CMSSignedData signedData) {
		this.signedData = signedData;
	}

	/**
	 * Sets the twince key.
	 *
	 * @param twinceKey            the twinceKey to set
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
	 * @throws CryptoException
	 */
	private byte[] sign(java.security.PrivateKey privateKey,
			List<X509Certificate> certificate, byte[] data)
			throws CryptoException {
		byte[] signedValue = null;
		try {
			SecurityConcepts.addProvider();

			CMSTypedData msg = new CMSProcessableByteArray(data);
			
			Store certs = new JcaCertStore(certificate);
			log.debug("Checking to see if we need to inject time....");
			final ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
			if (settings.getTimeInjectionSetting().isIncludeTime()) {
				final Attribute signingAttribute = new Attribute(
						CMSAttributes.signingTime, new DERSet(new DERUTCTime(
								settings.getTimeInjectionSetting()
										.getTimeSetter().GetCurrentTime())));
				signedAttributes.add(signingAttribute);
			}
			// Create the signing table
			final AttributeTable signedAttributesTable = new AttributeTable(
					signedAttributes);
			final DefaultSignedAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(
					signedAttributesTable);
			final JcaSimpleSignerInfoGeneratorBuilder builder = new JcaSimpleSignerInfoGeneratorBuilder()
					.setProvider(SecurityConcepts.getProviderName());
			builder.setSignedAttributeGenerator(signedAttributeGenerator);

			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

			for (int i = 0; i < certificate.size(); i++) {
				final SignerInfoGenerator signerGenerator = builder.build(
						settings.getHashingAlgorythm(), privateKey,
						certificate.get(i));

				gen.addSignerInfoGenerator(signerGenerator);
				gen.addCertificates(certs);
			}


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
					// ex.printStackTrace();
					throw new CryptoException(new CryptoError(
							GlobalErrorCode.FILE_IO_ERROR));
				}
			}
		} catch (IOException e) {
			throw new CryptoException(GlobalErrorCode.FILE_IO_ERROR);
		} catch (CertificateEncodingException e) {

			throw new CryptoException(GlobalErrorCode.CERT_INVALID_FORMAT);
		} catch (OperatorCreationException e) {
			throw new CryptoException(GlobalErrorCode.TXN_FAIL,
					e.getMessage());
		} catch (CMSException e) {
			throw new CryptoException(GlobalErrorCode.SIG_INVALID,
					e.getMessage());

		}
		if (PropertyFileConfiguration.DEBUG) {
			log.info("Value to be signed: " + new String(data)
					+ SecurityConcepts.newLine + " Signing Result : "
					+ new Base64(signedValue));
		}
		return signedValue;
	}

	/**
	 * Sign using a private key and representative public keys to be added to
	 * the signed text.
	 *
	 * @param key the key
	 * @param certificate the certificate
	 * @param data the data
	 * @return the byte[]
	 * @throws CryptoException the gbay crypto exception
	 */
	public byte[] sign(java.security.PrivateKey key,
			X509Certificate certificate, byte[] data)
			throws CryptoException {
		List<X509Certificate> cert = new ArrayList<X509Certificate>();
		cert.add(certificate);
		return sign(key, cert, data);
	}

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.provider.CryptoServiceProvider#sign(tools.pki.gbay.crypto.texts.PlainText)
	 */
	@Override
	public SignedText sign(PlainText text) throws CryptoException {
		return (SignedText) sign(text, null);
	}

	/**
	 * Use {@link KeyStorage} to sign a text. To sign using this function you
	 * need to set the KeyStorage First
	 *
	 * @param text the text
	 * @param selectingFunction the selecting function
	 * @return the signed text interface
	 * @throws CryptoException the gbay crypto exception
	 */
	public SignedTextInterface sign(PlainText text,
			KeySelectionInterface selectingFunction) throws CryptoException {
		twinceKey = keyStorage.getCoupleKey(selectingFunction);
		byte[] signedPlayLoad = sign(twinceKey.getPrivateKey(), twinceKey
				.getPublicKey().getCertificate(), text.toByte());
		List<CertificateInterface> signersList = new ArrayList<CertificateInterface>();
		signersList.add(twinceKey.getPublicKey());
		SignedTextInterface st = new SignedText(text.toString(),
				signedPlayLoad, signersList);
		return st;
	}

	/**
	 * Checks whether given X.509 certificate is self-signed.
	 *
	 * @param cert the cert
	 * @return true, if checks if is self signed
	 * @throws CertificateException the certificate exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws NoSuchProviderException the no such provider exception
	 */
	public static boolean isSelfSigned(X509Certificate cert)
			throws CertificateException, NoSuchAlgorithmException,
			NoSuchProviderException {
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

	/**
	 * *
	 * Verifies a signed text, if the signedText has it's own crl will verifies
	 * over it, if not it verifies over the CRL of SoftCert Object As for
	 * Issuers it will verifys to all issuers inside of signedText and SoftCert,
	 * if the text is signed with even only one trusted issuer it can be
	 * verified.
	 *
	 * @param text the text
	 * @param originalText the original text
	 * @return the verified text
	 * @throws CryptoException the gbay crypto exception
	 */
	@Override
	public VerifiedText verify(SignedText text, PlainText originalText)
			throws CryptoException {
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
	 * @throws CryptoException
	 */
	@SuppressWarnings("rawtypes")
	@Inject
	private VerifiedText VerifyAndValidate(SignedText signedText,
			PlainText OriginalText) throws CryptoException {
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
						throw new CryptoException(
								GlobalErrorCode.CERT_IS_SELF_SIGNED);
				} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
					throw new CryptoException(
							GlobalErrorCode.CERT_INVALID_FORMAT, e.getMessage());
				}

				caCert = getCaCert();
				if (caCert == null) {
					throw new CryptoException(
							GlobalErrorCode.CERT_ISSUER_NOT_SET);
				}
				log.debug("ca" + caCert);
				log.info("Checking for revokation...");
				obj.setRevoked(isRevoked());
				log.info("Extracting public key for verification...");
				CertificateValiditor mykey = new CertificateValiditor(settings,
						currentCert);
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
					log.info("Verification is done and signature is not verified");
					isVerified = false;
				}
			}
		} catch (CMSException e1) {
			obj.setValidated(false);
			log.error(e1);
			throw new CryptoException(new CryptoError(
					GlobalErrorCode.SIG_NOT_FOUND));
		} catch (CertificateExpiredException e) {
			log.debug(e);
			obj.setValidated(false);
		} catch (CertificateNotYetValidException e) {
			log.debug(e);
			obj.setValidated(false);
		} catch (OperatorCreationException e) {
			log.error(e);
			throw new CryptoException(new CryptoError(
					GlobalErrorCode.SIG_INVALID));
		} catch (CertificateException e) {
			log.error(e);
			throw new CryptoException(new CryptoError(
					GlobalErrorCode.CERT_INVALID_FORMAT));
		}
		obj.setValidated(isValidated);
		obj.setVerified(isVerified);
		return obj;
	}

	/**
	 * Check if cert is revoked, if you set certrepos URL to null and retry
	 * counts to -1 it will use default values in configuration.
	 *
	 * @return true, if checks if is revoked
	 * @throws CryptoException the gbay crypto exception
	 */
	public boolean isRevoked() throws CryptoException {
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
			throw new CryptoException(new CryptoError(
					GlobalErrorCode.CERT_CRL_NOT_FOUND));
		}
		return true;
	}

	/* 
	 * Encrypt a text based on a plain text 
	 * @see tools.pki.gbay.crypto.provider.CryptoServiceProvider#encrypt(tools.pki.gbay.crypto.texts.PlainText)
	 */
	@Override
	public EncryptedText encrypt(PlainText text) throws CryptoException {
		return null;
	}

	
}
