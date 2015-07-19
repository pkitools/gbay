package tools.pki.gbay.crypto.texts;

import java.util.Set;

import tools.pki.gbay.crypto.keys.CertificateValiditor;

/**
 * Interface to be used for verification results
 * @author Android
 *
 */
public interface VerificationInterface {

	/**
	 * @return the base64signedValue 
	 */
	public abstract String getBase64signedValue();

	/**
	 * @param base64signedValue the base64signedValue to set
	 */
	public abstract void setBase64signedValue(EncodedTextInterface base64signedValue);

	

	/**
	 * Means the text of signed text has been verified over the original text 
	 * @return the verified
	 */
	public abstract boolean isVerified();

	/**
	 * 
	 * @param verified the verified to set
	 */
	public abstract void setVerified(boolean verified);

	/**
	 * All the certificate inside the signed text were valid, not revoked and coming from trusted issuers
	 * @return the validated
	 */
	public abstract boolean isValidated();

	/**
	 * @param validated the validated to set
	 */
	public abstract void setValidated(boolean validated);

	/**
	 * Indicates if verified
	 * @return true if all verifications are passed
	 */
	public abstract boolean isPassed();


	/**
	 * @return all certificates that are in signature
	 */
	public abstract Set<CertificateValiditor> getCertificates();
	

}