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
package tools.pki.gbay.crypto.keys.validation;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;















import com.google.inject.Inject;

import tools.pki.gbay.configuration.SecurityConcepts;
import tools.pki.gbay.crypto.provider.SignatureSettingInterface;
import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.CryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;

/**
 * The Class CertificateValidator is to do  validation of certificates
 */
public class CertificateValidator {
	
	/**
	 * The Enum ValidationMethod.
	 */
	enum ValidationMethod {
		
		/** The check crl. */
		CHECK_CRL, 
 /** The check expiration date. */
 CHECK_EXPIRATION_DATE, 
 /** The check root. */
 CHECK_ROOT
	}

	/** The Constant log. */
	static final Logger log = Logger.getLogger(CertificateValidator.class);

//	/** Revocation list's address. */
//	private String[] CRLaddress = null;

	/** The result. {@link CertificateValidationResult} of the used functions */
	private CertificateValidationResult result = new CertificateValidationResult();

	/** List of {@link CertificateIssuer}s. */
	private CertificateChain trustedissuers;

	/** X509Certificate�that we want to validate it. */
	private X509Certificate cert;

	/** Allowed certificate issuers. */
//	private String trustedrootsdir;

	private X509CRL crl;

	/**
	 * Generate a validator object.
	 *
	 * @param cert            the X509certificate object which we want to validate it
	 * @param trustedroots            List of {@link CertificateIssuer}s<br>
	 *            The addresses should be absolute path.
	 *            <p>
	 *            certificate that are issued by these issuers can be trusted.
	 *            </p>
	 * @param crl the crl
	 */
	public CertificateValidator(X509Certificate cert,	CertificateChain trustedroots, X509CRL crl) {
		super();
		log.debug("Generating validator for " + cert.getSubjectDN());
		this.cert = cert;
		this.trustedissuers = trustedroots;
		this.crl = crl;
	}

	/**
	 * The Constructor.
	 *
	 * @param cert the cert
	 * @param trustedroot the trustedroot
	 * @param crl the crl
	 * @throws CryptoException the gbay crypto exception
	 */
	public CertificateValidator(X509Certificate cert,CertificateIssuer trustedroot, X509CRL crl) throws CryptoException {
		super();
		this.cert = cert;
		log.debug("Setting cert issuers");
		if (trustedroot !=null){
			this.trustedissuers = new CertificateChain();
		    trustedissuers.getRootIssuers().add(trustedroot);
		}
		else{
			log.error("trusted roots are null");
			throw new CryptoException(new CryptoError(GlobalErrorCode.CERT_ISSUER_NOT_SET));			
		}
		log.debug("setting cert CRL");
		if (crl!=null)
			this.crl = crl;
		else{
			throw new CryptoException(new CryptoError(GlobalErrorCode.CERT_CRL_NOT_SET));
		}
	}

	//@Inject
	SignatureSettingInterface settings;
	
	/**
	 * @param setting
	 * @param certificate
	 */
	@Inject
	public CertificateValidator(SignatureSettingInterface setting, X509Certificate certificate) {
		super();
		settings = setting;
		try {
			if (settings == null){
				log.error("Injecting done but Empty settings ");
			}
			trustedissuers =  settings.getIssuer(certificate);
		} catch (CryptoException e) {
			
			log.error(e);
		}
		crl = settings.getCrl(certificate);
		cert = certificate;
	}
/**
 * To validate a cert
 * @param certificate
 */
@Inject
	
	public CertificateValidator(X509Certificate certificate) {
		super();
		
		try {
			if (settings == null){
				log.error("Empty settings ");
			}
			trustedissuers =  settings.getIssuer(certificate);
		} catch (CryptoException e) {
			
			log.error(e);
		}
		crl = settings.getCrl(certificate);
		cert = certificate;	
}

	/**
	 * Checks if is valid.
	 *
	 * @return true, if checks if is valid
	 */
	public boolean isValid() {
		return isValid();
	}

	/**
	 * Validate.
	 *
	 * @return the certificate validation result
	 * @throws CryptoException the gbay crypto exception
	 */
	public CertificateValidationResult validate() throws CryptoException {
		CertificateValidationResult cvr = new CertificateValidationResult();
		if (crl != null){
			cvr.revoked = validateRevocation();
			}
		else{
			log.info("CRL is null");
		}
		cvr.expired = isExpired();
		cvr.notStarted = !isStarted();
		if (trustedissuers != null && trustedissuers.size()>0){
		try{
			log.info("Number of issuers : "+ trustedissuers.size());
			cvr.setInvalidCA(validateRoot());
		}
		catch (CryptoException e){
			throw new CryptoException(e);
		}
		}
		return cvr;
	}

	/**
	 * Gets the result.
	 *
	 * @param validationtypes the validationtypes
	 * @return the result
	 * @throws CryptoException the gbay crypto exception
	 */
	public CertificateValidationResult getResult(
			Set<ValidationMethod> validationtypes) throws CryptoException {
		CertificateValidationResult cvr = new CertificateValidationResult();
		if (validationtypes.contains(ValidationMethod.CHECK_CRL) && crl!=null) {
			cvr.revoked = validateRevocation();
		}
		if (validationtypes.contains(ValidationMethod.CHECK_EXPIRATION_DATE)) {
			cvr.expired = isExpired();
			cvr.notStarted = !isStarted();
		}
		if (validationtypes.contains(ValidationMethod.CHECK_ROOT)) {
			cvr.setInvalidCA(validateRoot());
		}
		return cvr;
	}

	/**
	 * check cert issuer DN if it's coming from a known CA. <br>
	 * It can verify over list of issuer names , list of root cert addresses or
	 * a folder containing root certs regarding to the way that object is
	 * constructed</br>
	 *
	 * @return true, if successful
	 * @throws CryptoException the gbay crypto exception
	 */
	public boolean validateRoot() throws CryptoException {

		log.debug("Validating root certs");
		cert.getPublicKey();
		boolean trusted = true;

		if (trustedissuers == null || trustedissuers.size() < 1) {
			log.error("No trusted issuer is in the system. ");
			
			throw new CryptoException(new CryptoError(
					GlobalErrorCode.CERT_ISSUER_NOT_FOUND));
		} else {
			trusted = validateIssuers();
		}
		return trusted;

	}

	/**
	 * Checks if the certificate is a valid one. it verifies the certificate
	 * chain over a root certificate.
	 * 
	 * @param caPath
	 *            the address of certificate authority's cer file
	 * @return True if chain is verified, false if chain can't be verified
	 * @throws CryptoException
	 */
	private boolean validateIssuers() throws CryptoException {
		{
		Set<String> caNames = new HashSet<String>();
			log.debug("Check the issuer");
		
			if (trustedissuers != null) {
				try {
					/**
					 * Put cert extracted from signature to ByteArrayInputStream
					 * and generate cert from there
					 */

					if (trustedissuers.size() >0 ) {
						PKIXCertPathValidatorResult result;
						try {
							result = verifyCertificate(cert, trustedissuers);
							log.debug(result.toString());
						} catch (NoSuchProviderException
								| CertPathBuilderException e) {
							return false;
						}
						return true;
					}

					else 
					{
						for (String string : caNames) {
							if (string != null){
								log.debug("Issuer did not contain root cert but just the name:"+ string + tools.pki.gbay.configuration.PropertyFileConfiguration.StarLine + "Cert issuer:"+cert.getIssuerDN().getName().toString());
								if (cert.getIssuerDN().getName().toString().contains(string))
									return true;

							}
						}
					}
				} catch (InvalidAlgorithmParameterException e) {
					log.error(e.getMessage());
					return false;
				} catch (NoSuchAlgorithmException e) {
					log.error(e.getMessage());
					return false;
				}

			} else {
				log.error("You haven't send any issuer to validate..");
				throw new CryptoException(new CryptoError(
						GlobalErrorCode.CERT_ISSUER_NOT_SET));
			}
		}
		return false;
	}

	/**
     * Attempts to build a certification chain for given certificate and to verify
     * it. Relies on a set of root CA certificates (trust anchors) and a set of
     * intermediate certificates (to be used as part of the chain).
     * @param cert - certificate for validation
     * @param trustedRootCerts - set of trusted root CA certificates
     * @param intermediateCerts - set of intermediate certificates
     * @return the certification chain (if verification is successful)
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws CertPathBuilderException 
     * @throws GeneralSecurityException - if the verification is not successful
     *      (e.g. certification path cannot be built or some certificate in the
     *      chain is expired)
     */
    private static PKIXCertPathBuilderResult verifyCertificate(X509Certificate cert,CertificateChain chain) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, CertPathBuilderException  {
         
        // Create the selector that specifies the starting certificate
        X509CertSelector selector = new X509CertSelector(); 
        selector.setCertificate(cert);
        Set<X509Certificate> interMediateCerts = new HashSet<X509Certificate>(); 
        // Create the trust anchors (set of root CA certificates)
        Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
        for (CertificateIssuer trustedRootCert : chain.rootIssuers) {
        	if (trustedRootCert.getCertificate()!=null)
            trustAnchors.add(new TrustAnchor(trustedRootCert.getCertificate(), null));
        }
         
        // Configure the PKIX certificate builder algorithm parameters
        PKIXBuilderParameters pkixParams = 
            new PKIXBuilderParameters(trustAnchors, selector);
         
        // Disable CRL checks (this is done manually as additional step)
        pkixParams.setRevocationEnabled(false);
     
        for (CertificateIssuer issuer : chain.intermediateIssuers) {
        	if (issuer.getCertificate()!=null)		
        		interMediateCerts.add(issuer.getCertificate());
        }
        // Specify a list of intermediate certificates
        CertStore intermediateCertStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(interMediateCerts), SecurityConcepts.getProviderName());
        pkixParams.addCertStore(intermediateCertStore);
     pkixParams.setRevocationEnabled(false);
        // Build and verify the certification chain
        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", SecurityConcepts.getProviderName());
        PKIXCertPathBuilderResult result = 
            (PKIXCertPathBuilderResult) builder.build(pkixParams);
        return result;
    }
	
	/**
	 * Validate period.
	 *
	 * @return true, if validate period
	 */
	public boolean validatePeriod() {
		return isExpired() && isStarted();
	}

	/**
	 * Checks if the certificate is expired.
	 * 
	 * @return true if certificate is expired
	 */
	public boolean isExpired() {
	
		boolean expired = false;
		Date notAfter = cert.getNotAfter();
		long currentTime = System.currentTimeMillis();
		long expiryTime = notAfter.getTime();
		log.debug(expiryTime + " Current time: " + currentTime);
		expired = (expiryTime < currentTime);
		result.expired = expired;
		return expired;
	}

	/**
	 * Checks if certificate validation period is started.
	 * 
	 * @return true, if is started
	 */
	public boolean isStarted() {
		boolean started = false;
		Date notBefore = cert.getNotBefore();
		long currentTime = System.currentTimeMillis();
		long startTime = notBefore.getTime();
		log.debug(startTime + " Current time: " + currentTime);
		started = (startTime <= currentTime);
		result.notStarted = !started;
		log.info("Certificate is started : "+started);
		return started;
	}

	/**
	 * Validate revocation.
	 *
	 * @return true, if validate revocation
	 * @throws CryptoException the gbay crypto exception
	 */
	public boolean validateRevocation() throws CryptoException {
		if (crl == null) {
			log.debug("crl in certificate validatore is null");
			throw new CryptoException(new CryptoError(GlobalErrorCode.CERT_CRL_NOT_FOUND));
		}
		return crl.isRevoked(cert);
	}

}
