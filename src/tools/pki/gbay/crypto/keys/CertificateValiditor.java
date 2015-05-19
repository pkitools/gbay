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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Set;

import tools.pki.gbay.crypto.keys.validation.CertificateChain;
import tools.pki.gbay.crypto.keys.validation.CertificateIssuer;
import tools.pki.gbay.crypto.keys.validation.CertificateValidationResult;
import tools.pki.gbay.crypto.keys.validation.CertificateValidator;
import tools.pki.gbay.crypto.provider.SignatureSettingInterface;
import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.CryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;
import tools.pki.gbay.util.general.CryptoFile;
import tools.pki.gbay.util.general.FileUtil;

import org.apache.log4j.Logger;

import com.google.inject.Inject;


//to add generating from file and validatings to StandardCertificate
public class CertificateValiditor extends StandardCertificate {

	
	Logger log = Logger.getLogger(CertificateValiditor.class);
	

/**
 * Read cert from byte array
 * @param content cert value;
 * @return X509certificate object
 * @throws CertificateException
 * @throws FileNotFoundException
 */
	public static X509Certificate getCertFromContent(byte[] content) throws CertificateException, FileNotFoundException {
		return FileUtil.GetCert(new ByteArrayInputStream(content));
	}

	
	protected File fileAddress;
	CertificateChain issuer;
	private boolean validated;
	private CertificateValidationResult validationResult;
	
	@Inject
	protected CertificateValiditor() {
	}

	public CertificateValiditor(File certificateFileAddress) throws CryptoException{
		this(fileToStream(certificateFileAddress));
			this.fileAddress = certificateFileAddress;
	}
	
	
	private static FileInputStream fileToStream(File file) throws CryptoException{
		System.err.println(file);
		FileInputStream fs =null;
		try {
			fs =	new FileInputStream(file);
		} catch (FileNotFoundException e) {
			System.out.println("File not found" + file.getAbsolutePath());
			throw new CryptoException(new CryptoError(GlobalErrorCode.FILE_NOT_FOUND));
		}
		return fs;
	}
	public CertificateValiditor(byte[] decode) throws CryptoException {
	this(new ByteArrayInputStream(decode));
	}
	protected CertificateValiditor(InputStream is) throws CryptoException{
		initiate(is); 
	}

	private void initiate(InputStream is) throws CryptoException {
		try {
			log.debug("Initiating cert...");
			extractCertDetail(FileUtil.GetCert(is));
			log.debug("Cert detail is extracted");
		} catch (CertificateException e) {
			throw new CryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT));
		}
	}

	
	public CertificateValiditor(CryptoFile file) throws CryptoException {
		this(file.getContent().toByte());
		if (file.getFile() != null)
		this.fileAddress = file.getFile();
	}


	
	/**
	 * Initiate a public key with an attached interface that will be run to get the issuer
	 * @param certificate
	 * @param setting 
	 * @param getIssuerFromCert
	 * @param crl
	 * @throws CryptoException
	 */
	@Inject
	public CertificateValiditor(SignatureSettingInterface setting, X509Certificate certificate) throws CryptoException {
	this.settings = setting;
		log.debug("Generating certificate validator...");

	extractCertDetail(certificate);
	log.debug("Certificate detail is extracted");
	
			this.validationResult = validate();
	}
	
	/**
	 * Initiate a public key with an attached interface that will be run to get the issuer
	 * @param certificate
	 * @param setting 
	 * @param getIssuerFromCert
	 * @param crl
	 * @throws CryptoException
	 */
	
	public CertificateValiditor(X509Certificate certificate) throws CryptoException {
		log.debug("Generating certificate validator...");

	extractCertDetail(certificate);
	log.debug("Certificate detail is extracted");
	
			this.validationResult = validate();
	}
	


	@Override
	public boolean equals(Object other) {
		 if (this == other) return true;
		 if (other instanceof X509Certificate)
			 return (X509Certificate)other== certificate;
		    if (other == null) return false;
			return false;
	}

	public java.security.cert.X509Certificate getCertificate() {
		return certificate;
	}

	/**
	 * @return the crl
	 */
	public X509CRL getCrl() {
		return crl;
	}

	/**
	 * @return the fileAddress
	 */
	public File getFileAddress() {
		return fileAddress;
	}



	/**
	 * @return the validationResult
	 */
	public CertificateValidationResult getValidationResult() {
		return validationResult;
	}

	/**

     * Checks whether given X.509 certificate is self-signed.

     */

    public boolean isSelfSigned()

            throws CryptoException {

        try {

            // Try to verify certificate signature with its own public key

        	java.security.PublicKey key = certificate.getPublicKey();

        	certificate.verify(key);

            return true;

        } catch (SignatureException sigEx) {
            return false;
        } catch (InvalidKeyException keyEx) {
            return false;

        } catch (CertificateException e) {
			throw new CryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT));
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_ALGORITHM));
		} catch (NoSuchProviderException e) {
			throw new CryptoException(new CryptoError(GlobalErrorCode.KEY_PROVIDER_NOT_FOUND));
		}

    }

	/**
	 * @return the validated
	 */
	public boolean isValidated() {
		return validated;
	}

	/**
	 * @param crl the crl to set
	 */
	public void setCrl(X509CRL crl) {
		this.crl = crl;
	}


	/**
	 * Sets the file address, note: This will also generate the certificate
	 * again
	 * 
	 * @param fileAddress
	 *            the fileAddress to set
	 * @throws CryptoException 
	 */
	public void setFileAddress(File fileAddress) throws CryptoException {
		this.fileAddress = fileAddress;
		try {
			initiate(new FileInputStream(fileAddress));
		} catch (FileNotFoundException e) {
			throw new CryptoException(new CryptoError(GlobalErrorCode.FILE_NOT_FOUND));
		}
	}


	/**
	 * Set the certificate's CA
	 * @param issuer
	 *            the issuer to set
	 */
	public void setIssuer(CertificateChain issuer) {
		this.issuer = issuer;
	}
	
	 /**
	  * Set as a validated cert
	 * @param validated
	 *            the validated to set
	 */
	public void setValidated(boolean validated) {
		this.validated = validated;
	}


	/**
	 * @param validationResult the validationResult to set
	 */
	public void setValidationResult(CertificateValidationResult validationResult) {
		this.validationResult = validationResult;
	}
	
	public CertificateValidationResult  validate(CertificateIssuer issuer) throws CryptoException {
		this.validated = true;	
		CertificateValidator cv = new CertificateValidator(certificate, issuer , crl);
		return cv.validate();		
	}


	public CertificateValidationResult validate() throws CryptoException {
		this.validated = true;
			log.info("Validating... " + settings.isEncapsulate());
		CertificateValidator cv = new CertificateValidator(settings, certificate);
			return cv.validate();
	}
	

}
