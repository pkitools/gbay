package tools.pki.gbay.crypto.provider;

import tools.pki.gbay.crypto.times.TimeInterface;


public class SignatureTime {

	protected boolean includeTime;
	protected TimeInterface timeSetter;
	public boolean isIncludeTime() {
		return includeTime;
	}
	public void setIncludeTime(boolean includeTime) {
		this.includeTime = includeTime;
	}
	public TimeInterface getTimeSetter() {
		return timeSetter;
	}
	public void setTimeSetter(TimeInterface timeSetter) {
		this.timeSetter = timeSetter;
	}
	public String getOid() {
		return oid;
	}
	public void setOid(String oid) {
		this.oid = oid;
	}
	protected String oid;	
}
