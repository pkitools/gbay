package tools.pki.gbay.crypto.keys.validation;


/**
 * Singleton class for settings of CrlCheckParameters
 * @author Araz
 *
 */
public class CrlCheckParameters {
	
	private static CrlCheckParameters instance = null;
	public static CrlCheckParameters getInstance(){
		if (instance == null){
			instance = new CrlCheckParameters();
		}
		return instance;
	}
private 	String certRepos;
private 	 int maxRetryRepos;
private 		int maxRetryCDP;
/**
 * @return the certRepos
 */
public  String getCertRepos() {
	return certRepos;
}
/**
 * @param certRepos the certRepos to set
 */
public  void setCertRepos(String certRepos) {
	this.certRepos = certRepos;
}

public void initiate(String certRepos,int maxRetryRepos, int maxRetryCDP){
	this.certRepos = certRepos;
	this.maxRetryCDP = maxRetryCDP;
	this.maxRetryRepos = maxRetryRepos;
}

/**
 * @return the maxRetryRepos
 */
public int getMaxRetryRepos() {
	return maxRetryRepos;
}
/**
 * @param maxRetryRepos the maxRetryRepos to set
 */
public void setMaxRetryRepos(int maxRetryRepos) {
	this.maxRetryRepos = maxRetryRepos;
}
/**
 * @return the maxRetryCDP
 */
public int getMaxRetryCDP() {
	return maxRetryCDP;
}
/**
 * @param maxRetryCDP the maxRetryCDP to set
 */
public void setMaxRetryCDP(int maxRetryCDP) {
	this.maxRetryCDP = maxRetryCDP;
}

}
