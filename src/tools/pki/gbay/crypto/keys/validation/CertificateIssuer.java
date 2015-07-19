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

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import tools.pki.gbay.configuration.PropertyFileConfiguration;
import tools.pki.gbay.crypto.keys.CertificateValiditor;
import tools.pki.gbay.errors.CryptoException;

import org.apache.log4j.Logger;


/**
 * Representing a CA
 * @author Araz Farhang 
 *
 */
public class CertificateIssuer extends CertificateValiditor {
	Logger log = Logger.getLogger(CertificateIssuer.class);

	/** The is intermediate. */
	private boolean isIntermediate;

	/**
	 * generate certificate issuer
	 * @param name name of issuer (as appeared in DN or a part of DN)
	 * @param certificates {@link X509Certificate} of the issuer
	 * @throws NoSuchAlgorithmException 
	 * @throws CertificateEncodingException 
	 * @throws CryptoException 
	 */
	public CertificateIssuer(String name, X509Certificate certificates) throws CertificateEncodingException, NoSuchAlgorithmException, CryptoException {
		super(certificates);
		log.debug("Certificate issuer is constracting " + name);
		this.name = name;
		this.hascert = true;
	}
	/**
	 * Generate certificate issuers with their name and cer file
	 * @param name  name of issuer (as appeared in DN or a part of DN)
	 * @param fileaddress address of CA cert file
	 * @throws CryptoException 
	 */
	public CertificateIssuer(String name, File fileaddress) throws CryptoException {
		super(fileaddress);
		log.debug(PropertyFileConfiguration.StarLine+"Issuer for "+name+" has been created from : " + fileaddress.getAbsolutePath());
		log.debug("Root cert subjectDN : " +this.getSubjectDN()+PropertyFileConfiguration.StarLine);
		this.name = name;
		this.hascert = true;
	}
	
	
	
	/**
	 * Generate certificate issuer just with it's name <br> Useful for issuers that their root certificate is not available
	 * @param name name of issuer
	 */
	public CertificateIssuer(String name) {
	super();
		this.name = name;
		this.hascert = false;
	}
	
  
	
	/**
	 * Get name of issuer
	 * @return name of issuer
	 */
	public String getName() {
		return name;
	}
	/**
	 * Set name of issuer
	 * @param name name of issuer
	 */
	public void setName(String name) {
		this.name = name;
	}
	/**
	 * set address of CA cert file
	 * @throws CryptoException 
	 */

	@Override
	public void setFileAddress(File fileAddress) throws CryptoException {
		super.setFileAddress(fileAddress);
		setHascert();
	}
	
	
	private String name;
	
	/**
	 * Get {@link X509Certificate} of the issuer
	 * @return {@link X509Certificate} of the issuer
	 */
	public X509Certificate getCertificates() {
		return certificates;
	}
	/**
	 * Set {@link X509Certificate} of the issuer
	 * @param certificates {@link X509Certificate} of the issuer
	 */
	public void setCertificates(X509Certificate certificates) {
		setHascert();
		this.certificates = certificates;
	}
	private X509Certificate certificates;
	
	private boolean hascert;
	/**
	 * Indicates if the root certificate of issuer is available or not 
	 * @return true if either certificate path or {@link X509Certificate} of root cert is specified
	 */
	public boolean hasCert() {
		return hascert;
	}
	
	/**
	 * Sets the certificate validity, 
	 * @param hascert
	 */
	private void setHascert() {
		this.hascert = true;
	}
	/**
	 * @return the isIntermediate
	 */
	public boolean isIntermediate() {
		return isIntermediate;
	}
	/**
	 * @param isIntermediate the isIntermediate to set
	 */
	public void setIntermediate(boolean isIntermediate) {
		this.isIntermediate = isIntermediate;
	}
	

}
