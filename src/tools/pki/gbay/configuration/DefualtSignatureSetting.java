package tools.pki.gbay.configuration;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

import com.google.inject.Inject;
import com.google.inject.Provider;

import tools.pki.gbay.crypto.keys.KeyStorage.CoupleKey;
import tools.pki.gbay.crypto.keys.validation.CertificateIssuer;
import tools.pki.gbay.crypto.keys.validation.CrlCheckParameters;
import tools.pki.gbay.crypto.provider.CaFinderInterface;
import tools.pki.gbay.crypto.provider.CrlFinderInterface;
import tools.pki.gbay.crypto.provider.KeySelectionInterface;
import tools.pki.gbay.crypto.provider.SignatureSettingInterface;
import tools.pki.gbay.crypto.provider.SignatureTime;
import tools.pki.gbay.crypto.times.TimeInterface;
import tools.pki.gbay.errors.GbayCryptoException;

public class DefualtSignatureSetting implements SignatureSettingInterface {
	
	final SignatureTime signingTimeSettings;
	
	
	@Inject DefualtSignatureSetting(SignatureTime st) {
//		 SignatureTime myst =	new SignatureTime();
		signingTimeSettings = st;
		
		encapsulate = true;
		signatureTime.setOid("1.2.840.113549.1.9.5");
	
		this.hashingAlgorythm = "SHA1withRSA";
		
				
	}
	
	
	
	
	
	public boolean isEncapsulate() {
		return encapsulate;
	}

	public void setEncapsulate(boolean encapsulate) {
		this.encapsulate = encapsulate;
	}
	
	public String getHashingAlgorythm() {
		return hashingAlgorythm;
	}
	public void setHashingAlgorythm(String hashingAlgorythm) {
		this.hashingAlgorythm = hashingAlgorythm;
	}
	protected	boolean encapsulate;
 	protected SignatureTime signatureTime;
 	protected String hashingAlgorythm;

	private CrlFinderInterface getCrlCaller;
	private CaFinderInterface issuerCaller;
	
	private KeySelectionInterface selectKeyFunction;
	public KeySelectionInterface getSelectKeyFunction() {
		return selectKeyFunction;
	}
	public void setSelectKeyFunction(KeySelectionInterface selectKeyFunction) {
		this.selectKeyFunction = selectKeyFunction;
	}

	
	@Override
	public SignatureTime getTimeInjectionSetiion() {
		
		return signatureTime;
	}

	@Override
	public Set<CertificateIssuer> getIssuer(X509Certificate currentCert)
			throws GbayCryptoException {
		return null;
	}

	@Override
	public X509CRL getCrl(X509Certificate cert) {
		return null;
	}

	@Override
	public Integer selectKey(List<CoupleKey> keyCouples) {
		// TODO Auto-generated method stub
		return null;
	}

 
}
