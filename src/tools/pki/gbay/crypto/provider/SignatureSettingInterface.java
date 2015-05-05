package tools.pki.gbay.crypto.provider;


public interface SignatureSettingInterface extends CaFinderInterface, CrlFinderInterface, KeySelectionInterface {

	public abstract SignatureTime getTimeInjectionSetiion();


	public abstract boolean isEncapsulate();


	public abstract String getHashingAlgorythm();
	
	
}