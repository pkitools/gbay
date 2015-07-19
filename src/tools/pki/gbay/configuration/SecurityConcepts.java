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

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The Class SecurityConcepts. contents basic configurations and values for Gbay
 */
public class SecurityConcepts {
	
	  /**
	 * Indicates if we are on debug mode
	 */
	public static boolean DEBUG = true;


	  /** The new line. */
	  public static String newLine = System.getProperty("line.separator");
	  /** The Star line. */
	  public static String StarLine = newLine+"*****************************************************************************************************"+newLine;

	  
	  /** The Constant DEFUALTISSUERFILE. */
	  protected static final String CONFIG_FILE = "config.properties";

	  protected static final String DEFUALTISSUERFILE = "trust.conf"; 

	

	   /**
	    * The Constructor.
	    */

	/**
	 * Adds the provider.
	 */
	public static void addProvider(){
		Security.addProvider(new BouncyCastleProvider());
	}
	
	/**
	 * Gets the provider name.
	 *
	 * @return the provider name
	 */
	public static String getProviderName(){
		return "BC";
	}
}
