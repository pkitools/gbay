package tools.pki.gbay.interfaces;


import tools.pki.gbay.configuration.PropertyFileConfiguration;
import tools.pki.gbay.crypto.provider.SignatureTime;

import com.google.inject.Singleton;



/**
 * Implement this class to define your own settings based on propertyfile, db or whatever
 * @author Android
 *
 */
@com.google.inject.ImplementedBy(PropertyFileConfiguration.class)
public interface SignatureSettingInterface extends CaFinderInterface, CrlFinderInterface, KeySelectionInterface {

	
	/**
	 * @see SignatureTime
	 * @return Signature Time Settings 
	 */
	public abstract SignatureTime getTimeInjectionSetting();


	/**
	 * 
	 * @return true if you want to include original text in your signatures
	 */
	public abstract boolean isEncapsulate();


	/**
	 * 
	 * @return Hashing algorithm you want to use in your project
	 */
	public abstract String getHashingAlgorythm();
	
	
}