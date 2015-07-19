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
package tools.pki.gbay.configuration;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import com.google.inject.Inject;

import tools.pki.gbay.crypto.keys.KeyStorage.CoupleKey;
import tools.pki.gbay.crypto.keys.validation.CertificateChain;
import tools.pki.gbay.crypto.keys.validation.CertificateIssuer;
import tools.pki.gbay.crypto.provider.CaFinderInterface;
import tools.pki.gbay.crypto.provider.CrlFinderInterface;
import tools.pki.gbay.crypto.provider.KeySelectionInterface;
import tools.pki.gbay.crypto.provider.SignatureSettingInterface;
import tools.pki.gbay.crypto.provider.SignatureTime;
import tools.pki.gbay.errors.CryptoException;

/**
 * Defualt settings of signatures
 * The Class DefualtSignatureSetting.
 */
public class DefualtSignatureSetting implements SignatureSettingInterface {
	
	/** The signing time settings. */
	final SignatureTime signingTimeSettings;
	
	
	/**
	 * The Constructor.
	 *
	 * @param st the st
	 */
	@Inject DefualtSignatureSetting(SignatureTime st) {
//		 SignatureTime myst =	new SignatureTime();
		signingTimeSettings = st;
		
		encapsulate = true;
		signatureTime.setOid("1.2.840.113549.1.9.5");
	
		this.hashingAlgorythm = "SHA1withRSA";
		
				
	}
	
	
	
	
	
	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.provider.SignatureSettingInterface#isEncapsulate()
	 */
	public boolean isEncapsulate() {
		return encapsulate;
	}

	/**
	 * Sets the encapsulate.
	 *
	 * @param encapsulate the encapsulate
	 */
	public void setEncapsulate(boolean encapsulate) {
		this.encapsulate = encapsulate;
	}
	
	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.provider.SignatureSettingInterface#getHashingAlgorythm()
	 */
	public String getHashingAlgorythm() {
		return hashingAlgorythm;
	}
	
	/**
	 * Sets the hashing algorythm.
	 *
	 * @param hashingAlgorythm the hashing algorythm
	 */
	public void setHashingAlgorythm(String hashingAlgorythm) {
		this.hashingAlgorythm = hashingAlgorythm;
	}
	
	/** The encapsulate. */
	protected	boolean encapsulate;
 	
	 /** The signature time. */
	 protected SignatureTime signatureTime;
 	
	 /** The hashing algorythm. */
	 protected String hashingAlgorythm;

	private CrlFinderInterface getCrlCaller;
	private CaFinderInterface issuerCaller;
	
	private KeySelectionInterface selectKeyFunction;
	
	/**
	 * Gets the select key function.
	 *
	 * @return the select key function
	 */
	public KeySelectionInterface getSelectKeyFunction() {
		return selectKeyFunction;
	}
	
	/**
	 * Sets the select key function.
	 *
	 * @param selectKeyFunction the select key function
	 */
	public void setSelectKeyFunction(KeySelectionInterface selectKeyFunction) {
		this.selectKeyFunction = selectKeyFunction;
	}

	
	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.provider.SignatureSettingInterface#getTimeInjectionSetiion()
	 */
	@Override
	public SignatureTime getTimeInjectionSetting() {
		
		return signatureTime;
	}

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.provider.CaFinderInterface#getIssuer(java.security.cert.X509Certificate)
	 */
	@Override
	public CertificateChain getIssuer(X509Certificate currentCert)
			throws CryptoException {
		return null;
	}

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.provider.CrlFinderInterface#getCrl(java.security.cert.X509Certificate)
	 */
	@Override
	public X509CRL getCrl(X509Certificate cert) {
		return null;
	}

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.provider.KeySelectionInterface#selectKey(java.util.List)
	 */
	@Override
	public Integer selectKey(List<CoupleKey> keyCouples) {
		// TODO Auto-generated method stub
		return null;
	}

 
}
