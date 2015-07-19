package tools.pki.gbay.crypto.provider;


import tools.pki.gbay.configuration.PropertyFileConfiguration;

import com.google.inject.Singleton;



@com.google.inject.ImplementedBy(PropertyFileConfiguration.class)
public interface SignatureSettingInterface extends CaFinderInterface, CrlFinderInterface, KeySelectionInterface {

	
	public abstract SignatureTime getTimeInjectionSetting();


	public abstract boolean isEncapsulate();


	public abstract String getHashingAlgorythm();
	
	
}