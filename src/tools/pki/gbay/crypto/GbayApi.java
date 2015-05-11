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
package tools.pki.gbay.crypto;

import org.apache.log4j.Logger;

import tools.pki.gbay.configuration.PropertyFileConfiguration;
import tools.pki.gbay.configuration.SecurityConcepts;
import tools.pki.gbay.crypto.keys.CertificateValiditor;
import tools.pki.gbay.crypto.keys.KeyStorage;
import tools.pki.gbay.crypto.provider.SignatureSettingInterface;
import tools.pki.gbay.crypto.provider.SoftCert;
import tools.pki.gbay.crypto.texts.Base64;
import tools.pki.gbay.crypto.texts.PlainText;
import tools.pki.gbay.crypto.texts.SignedText;
import tools.pki.gbay.crypto.texts.VerifiedText;
import tools.pki.gbay.errors.GbayCryptoException;
import tools.pki.gbay.util.general.CryptoFile;

import com.google.inject.Inject;
import com.google.inject.Singleton;

@Singleton
public class GbayApi  {
	private static final Logger logger = Logger.getLogger(GbayApi.class);

	private static GbayApi instance;

	@Inject
	private SignatureSettingInterface settings;
	 //setter method injector
    
	protected GbayApi() {
		
		 new PropertyFileConfiguration();
	//	SecurityConcepts.addProvider();
	}

	public SignedText sign(byte[]pfx,String pin,String messageToSign) throws GbayCryptoException{

		SoftCert sc = new SoftCert(new KeyStorage(pin.toCharArray(),new PlainText(pfx)));
		SignedText st =	sc.sign(new PlainText(messageToSign));
	//	st.toBase64()
		return st;
	}
	
	public VerifiedText verify(String originalText,byte[] signedtext) throws GbayCryptoException{
		
		logger.info("Verify function is called from API...");
		logger.debug("Original Text : "+ originalText + "   SignedText:" + new String(signedtext) );
		SignedText st = new SignedText(originalText, signedtext);
		logger.debug("Signed Text Object Generated" + SecurityConcepts.StarLine);
		SoftCert sc = new SoftCert();
		logger.debug("SoftCert Object Generated" + SecurityConcepts.StarLine);
		
		return	(VerifiedText) st.verify(sc);
		
		
	}
	
	public  class P12Files extends KeyStorage {

		public P12Files(CryptoFile file) throws GbayCryptoException {
			super(file);
		}

		public P12Files(Base64 fileContent, char[] pin) throws GbayCryptoException {
			super(pin, fileContent);
		}

	}

	public class CertFile extends CertificateValiditor {
		public CertFile(CryptoFile file) throws GbayCryptoException {
			super(file);
		}
		
		public CertFile(Base64 fileContent) throws GbayCryptoException{
			super(fileContent.decode());
		}
	}

	public static GbayApi getInstance() {
		if (instance == null)
			instance = new GbayApi();
		return instance;
	}
}
