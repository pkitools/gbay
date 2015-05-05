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

package tools.pki.gbay.configuration;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import com.google.inject.Singleton;

import tools.pki.gbay.crypto.keys.KeyStorage.CoupleKey;
import tools.pki.gbay.crypto.keys.validation.CertificateIssuer;
import tools.pki.gbay.crypto.provider.CaFinderInterface;
import tools.pki.gbay.crypto.provider.CrlFinderInterface;
import tools.pki.gbay.crypto.provider.SignatureSettingInterface;
import tools.pki.gbay.crypto.provider.SignatureTime;
import tools.pki.gbay.crypto.times.TimeInterface;
import tools.pki.gbay.errors.GbayCryptoException;
import tools.pki.gbay.util.general.PropertyLoader;

@Singleton
public class PropertyFileConfiguration extends SecurityConcepts implements SignatureSettingInterface
{

  public static boolean DEBUG = true;
  public static String newLine = System.getProperty("line.separator");
  public static final String DEFUALTISSUERFILE = "trust.conf"; 
  private static final String CONFIG_FILE = "config.properties";
  private static final boolean SAVE_SETTINGS = true;
  private static final String SIG_ATTACHED = "signature.settings.attached";
  private static final String SIG_ALGO =	 "signature.setting.hashing.algo";
  private static final String	SIG_TIME_INCLUDE =	  "signature.settings.time.include";
	private static final String	SIG_TIME_PROVIDER =	  "signature.settings.time.provider";
	private static final String	SIG_TIME_OID =	  "signature.settings.time.oid";
	private static final String	SIG_ISSUER_CALLER =	  "signature.settings.issuer.caller";
	private static final String	SIG_CRL_CALLER =	  "signature.settings.crl.caller";
	
  
  public static String getDefualtCaListFile(){
  return DEFUALTISSUERFILE;
  }
  public static String StarLine = newLine+"*****************************************************************************************************"+newLine;
  public static void debug(Object text){
	  if (PropertyFileConfiguration.DEBUG){
		  System.out.println(text);
	  }
  }

   public PropertyFileConfiguration() {

	  PropertyLoader.initiate(CONFIG_FILE, SAVE_SETTINGS);
		PropertyLoader.loadProperties();	
}





@Override
public Set<CertificateIssuer> getIssuer(X509Certificate currentCert)
		throws GbayCryptoException {
	
	 Class<?> c;
	try {
		c = Class.forName(PropertyLoader.getString(SIG_ISSUER_CALLER));
		 CaFinderInterface issuerCaller = (CaFinderInterface) c.newInstance();
		 return issuerCaller.getIssuer(currentCert);
		
		 
		 
	} catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	 return null;
	 
}



@Override
public X509CRL getCrl(X509Certificate cert) {
	Class<?> b;
	try {
		b = Class.forName(PropertyLoader.getString(SIG_CRL_CALLER));
		 CrlFinderInterface crlCaller = (CrlFinderInterface) b.newInstance();
		 return crlCaller.getCrl(cert);
	} catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	return null;

}



@Override
public Integer selectKey(List<CoupleKey> keyCouples) {
	// TODO Auto-generated method stub
	return null;
}



@Override
public SignatureTime getTimeInjectionSetiion() {
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
		st =null;
	}
return st;
	} catch (ClassNotFoundException e) {
		return null;
	} catch (InstantiationException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (IllegalAccessException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	return null;
}



@Override
public boolean isEncapsulate() {
	return PropertyLoader.getBoolean(SIG_ATTACHED);
}



@Override
public String getHashingAlgorythm() {
	return PropertyLoader.getSystemString(SIG_ALGO);
}

}