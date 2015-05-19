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

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.collections.map.HashedMap;

import tools.pki.gbay.crypto.provider.SoftCert;
import tools.pki.gbay.errors.CryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;

/**
 * The Class CertificateChain.
 */
public class CertificateChain {

	protected Set<CertificateIssuer> rootIssuers;
	protected Set<CertificateIssuer> intermediateIssuers;

	public CertificateChain() {
		super();
	
		rootIssuers = new  HashSet<CertificateIssuer>();
		intermediateIssuers = new HashSet<CertificateIssuer>();
	}
	
	public void AddIssuer(CertificateIssuer additionalCert) throws CryptoException{

		try {
			if (additionalCert.hasCert() && additionalCert.getCertificate()!=null)
			if (SoftCert.isSelfSigned(additionalCert.getCertificate())) {
			        rootIssuers.add(additionalCert);
			    } else {
			        intermediateIssuers.add(additionalCert);
			    }
		} catch (CertificateException | NoSuchAlgorithmException
				| NoSuchProviderException e) {

			throw new CryptoException(GlobalErrorCode.CERT_INVALID_FORMAT);
		}
	}
	
	public CertificateChain(Set<CertificateIssuer> rootIssuers,
			Set<CertificateIssuer> intermediateIssuers) {
		this();
		this.rootIssuers = rootIssuers;
		this.intermediateIssuers = intermediateIssuers;
	}
	/**
	 * @return the rootIssuers
	 */
	public Set<CertificateIssuer> getRootIssuers() {
		return rootIssuers;
	}
	/**
	 * @param rootIssuers the rootIssuers to set
	 */
	public void setRootIssuers(Set<CertificateIssuer> rootIssuers) {
		this.rootIssuers = rootIssuers;
	}
	/**
	 * @return the intermediateIssuers
	 */
	public Set<CertificateIssuer> getIntermediateIssuers() {
		return intermediateIssuers;
	}
	/**
	 * @param intermediateIssuers the intermediateIssuers to set
	 */
	public void setIntermediateIssuers(Set<CertificateIssuer> intermediateIssuers) {
		this.intermediateIssuers = intermediateIssuers;
	}
	public int size() {
		
		return rootIssuers.size()+intermediateIssuers.size();
	}
}
