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

package tools.pki.gbay.crypto.texts;

import java.io.File;

import tools.pki.gbay.crypto.provider.CryptoServiceProvider;
import tools.pki.gbay.errors.CryptoException;

/**
 * A normal text which can be used for crypto operations and has basic functionalities attaches
 * @author Araz
 */
public class PlainText extends BasicText{

	/**
	 * Construct the PlainText for future use
	 */
	public PlainText() {
		super("");
	}
	
	
	
	/**
	 * Generate a text from encoded text
	 * @param encodedText
	 */
	public PlainText(EncodedTextInterface encodedText) {
		super(encodedText);
	}



	
	/**
	 * Generate text from byte array
	 * @param content
	 */
	public PlainText(byte[] content) {
		super(content);
	}



	/**
	 * Generate text from a file
	 * @param container
	 * @throws CryptoException
	 */
	public PlainText(File container) throws CryptoException {
		super(container);
	}



	/**
	 * Generate text from string
	 * @param text
	 */
	public PlainText(String text) {
		super(text);
	}
	

	
	/**
	 * Sign the text using a provider
	 * @param signiner
	 * @return Signature
	 * @throws CryptoException
	 */
	public SignedText sign(CryptoServiceProvider signiner) throws CryptoException{
		return signiner.sign(this);    	
    }
    
    /**
     * Encrypt the text
     * @param encryptor
     * @return encrypted text
     * @throws CryptoException
     */
    public EncryptedText encrypt(CryptoServiceProvider encryptor) throws CryptoException{
    	return encryptor.encrypt(this);
    }
    
}
