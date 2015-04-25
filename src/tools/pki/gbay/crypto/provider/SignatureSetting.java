package tools.pki.gbay.crypto.provider;

public class SignatureSetting {
	
	public SignatureSetting(boolean encapsulate, SignatureTime signatureTime,
			String hashingAlgorythm) {
		super();
		this.encapsulate = encapsulate;
		this.signatureTime = signatureTime;
		this.hashingAlgorythm = hashingAlgorythm;
	}
	public boolean isEncapsulate() {
		return encapsulate;
	}
	public void setEncapsulate(boolean encapsulate) {
		this.encapsulate = encapsulate;
	}
	public SignatureTime getSignatureTime() {
		return signatureTime;
	}
	public void setSignatureTime(SignatureTime signatureTime) {
		this.signatureTime = signatureTime;
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

 
}
