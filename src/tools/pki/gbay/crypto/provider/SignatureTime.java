package tools.pki.gbay.crypto.provider;

import tools.pki.gbay.crypto.times.TimeInterface;


/**
 * Setting for the time in the PKCS#7 Signature
 * @author Android
 *
 */
public class SignatureTime {

	protected boolean includeTime;
	protected TimeInterface timeSetter;
	/**
	 * 
	 * @return true if time shall be included in signature
	 */
	public boolean isIncludeTime() {
		return includeTime;
	}
	
	/**
	 * @param includeTime  true if time shall be included in signature
	 */
	public void setIncludeTime(boolean includeTime) {
		this.includeTime = includeTime;
	}
	/**
	 * @return the class used for setting the time
	 */
	public TimeInterface getTimeSetter() {
		return timeSetter;
	}
	
	/**
	 * @param timeSetter  the class to be used for setting the time
	 */
	public void setTimeSetter(TimeInterface timeSetter) {
		this.timeSetter = timeSetter;
	}
	/**
	 * @return OID of SigningTime in signature
	 */
	public String getOid() {
		return oid;
	}
	
	/**
	 * @param oid  OID of SigningTime in signature
	 */
	public void setOid(String oid) {
		this.oid = oid;
	}
	protected String oid;	
}
