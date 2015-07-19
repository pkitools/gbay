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

import tools.pki.gbay.crypto.keys.KeyStorage.CoupleKey;
import tools.pki.gbay.crypto.keys.validation.CertificateChain;
import tools.pki.gbay.crypto.provider.SignatureTime;
import tools.pki.gbay.crypto.times.TimeInterface;
import tools.pki.gbay.errors.CryptoException;
import tools.pki.gbay.interfaces.CaFinderInterface;
import tools.pki.gbay.interfaces.CrlFinderInterface;
import tools.pki.gbay.interfaces.ErrorsSettingInterface;
import tools.pki.gbay.interfaces.HardwareSettingsInterface;
import tools.pki.gbay.interfaces.KeySelectionInterface;
import tools.pki.gbay.interfaces.SignatureSettingInterface;
import tools.pki.gbay.util.general.PropertyLoader;

/**
 * The Class PropertyFileConfiguration.
 * Is providing all configurations that Gbay Needs from property files by implementing SignatureSettingInterface and ErrorsSettingInterface
 * @see SignatureSettingInterface @see {@link ErrorsSettingInterface}
 */
//@Singleton
public class PropertyFileConfiguration extends SecurityConcepts implements SignatureSettingInterface , ErrorsSettingInterface , HardwareSettingsInterface
{

  /** The debug. */
  
  private static final boolean SAVE_SETTINGS = true;
  	private static final String SIG_ATTACHED = "signature.settings.attached";
  	private static final String SIG_ALGO =	 "signature.setting.hashing.algo";
  	private static final String	SIG_TIME_INCLUDE =	  "signature.settings.time.include";
	private static final String	SIG_TIME_PROVIDER =	  "signature.settings.time.provider";
	private static final String	SIG_TIME_OID =	  "signature.settings.time.oid";
	private static final String	SIG_ISSUER_CALLER =	  "signature.settings.issuer.caller";
	private static final String	SIG_CRL_CALLER =	  "signature.settings.crl.caller";
	private static final String SIG_KEY_SELECTOR =  "signature.settings.key.caller";
	private static final String SIG_HARDWARE_KEY_SELECTOR =  "signature.settings.hardware.key.caller";

	/**
 * Default constructor for loading settings of GBay from property files.
 * It initiates and loads the configuration file
 */
public PropertyFileConfiguration() {

	  PropertyLoader.initiate(CONFIG_FILE, SAVE_SETTINGS);
		PropertyLoader.loadProperties();	
}





/* 
 * Provide CA certificates from class spicified in property file
 * @see tools.pki.gbay.crypto.provider.CaFinderInterface#getIssuer(java.security.cert.X509Certificate)
 */
@Override
public CertificateChain getIssuer(X509Certificate currentCert)
		throws CryptoException {
	
	 Class<?> c;
	try {
		c = Class.forName(PropertyLoader.getString(SIG_ISSUER_CALLER));
		 CaFinderInterface issuerCaller = (CaFinderInterface) c.newInstance();
		 return issuerCaller.getIssuer(currentCert);
		
		 
		 
	} catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
		e.printStackTrace();
	}
	 return null;
	 
}



/* (non-Javadoc)
 * @see tools.pki.gbay.crypto.provider.CrlFinderInterface#getCrl(java.security.cert.X509Certificate)
 */
@Override
public X509CRL getCrl(X509Certificate cert) {
	Class<?> b;
	try {
		b = Class.forName(PropertyLoader.getString(SIG_CRL_CALLER));
		 CrlFinderInterface crlCaller = (CrlFinderInterface) b.newInstance();
		 return crlCaller.getCrl(cert);
	} catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
		e.printStackTrace();
	}
	return null;

}



/* (non-Javadoc)
 * @see tools.pki.gbay.crypto.provider.KeySelectionInterface#selectKey(java.util.List)
 */
@Override
public Integer selectKey(List<CoupleKey> keyCouples) {
	Class<?> b;
	try {
		b = Class.forName(PropertyLoader.getString(SIG_KEY_SELECTOR));
		 KeySelectionInterface keyCaller = (KeySelectionInterface) b.newInstance();
		 return keyCaller.selectKey(keyCouples);
	} catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
		e.printStackTrace();
	}
	return null;

}



/* (non-Javadoc)
 * @see tools.pki.gbay.crypto.provider.SignatureSettingInterface#getTimeInjectionSetiion()
 */
@Override
public SignatureTime getTimeInjectionSetting() {
	try {
	boolean includetime = PropertyLoader.getBoolean(SIG_TIME_INCLUDE);

	SignatureTime st = new SignatureTime();
	if (includetime){
	
		st.setOid(PropertyLoader.getString(SIG_TIME_OID));
		st.setIncludeTime(true);
		 Class<?> b;
		
			b = Class.forName(PropertyLoader.getString(SIG_TIME_PROVIDER));
		
		  TimeInterface timeprv = (TimeInterface) b.newInstance();
			st.setTimeSetter(timeprv);		  
	
	}
	 else{
		st.setIncludeTime(false);
	}
return st;
	} catch (ClassNotFoundException e) {
		return null;
	} catch (InstantiationException e) {
		e.printStackTrace();
	} catch (IllegalAccessException e) {
		e.printStackTrace();
	}
	return null;
}



/* (non-Javadoc)
 * @see tools.pki.gbay.crypto.provider.SignatureSettingInterface#isEncapsulate()
 */
@Override
public boolean isEncapsulate() {
	return PropertyLoader.getBoolean(SIG_ATTACHED);
}



/* (non-Javadoc)
 * @see tools.pki.gbay.crypto.provider.SignatureSettingInterface#getHashingAlgorythm()
 */
@Override
public String getHashingAlgorythm() {
	return PropertyLoader.getSystemString(SIG_ALGO);
}





@Override
public long selectCertHandlerFromList(long[] availableCertificates) {
	Class<?> b;
	try {
		b = Class.forName(PropertyLoader.getString(SIG_KEY_SELECTOR));
		 HardwareSettingsInterface keyCaller = (HardwareSettingsInterface) b.newInstance();
		 return keyCaller.selectCertHandlerFromList(availableCertificates);
	} catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
		e.printStackTrace();
	}
	return 0;
}

}