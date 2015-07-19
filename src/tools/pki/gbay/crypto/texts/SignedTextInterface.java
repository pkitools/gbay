package tools.pki.gbay.crypto.texts;

import java.util.List;
import java.util.Set;

import tools.pki.gbay.crypto.keys.CertificateInterface;
import tools.pki.gbay.crypto.keys.validation.CertificateChain;
import tools.pki.gbay.crypto.keys.validation.CertificateIssuer;
import tools.pki.gbay.crypto.keys.validation.CertificateRevocationList;
import tools.pki.gbay.crypto.provider.CryptoServiceProvider;
import tools.pki.gbay.errors.CryptoException;

/**
 * @author Android
 *
 */
public interface SignedTextInterface {


	/**
	 * To be converted to base 64 encoded value
	 * @return base64 encoded
	 */
	public abstract EncodedTextInterface toBase64();

	/**
	 * Signed value is the none-encoded signature
	 * @return the signedVal
	 */
	public abstract byte[] getSignedVal();

	/**
	 * @param signedVal the signedVal to set
	 */
	public abstract void setSignedVal(byte[] signedVal);

	/**
	 * @return the originalText
	 */
	public abstract PlainText getOriginalText();

	/**
	 * @param originalText the originalText to set
	 */
	public abstract void setOriginalText(PlainText originalText);

	/**
	 * To be verified
	 * @param csp
	 * @return verification result
	 * @throws CryptoException
	 */
	public abstract VerificationInterface verify(CryptoServiceProvider csp)
			throws CryptoException;

	/**
	 * @return the caCert
	 */
	public abstract CertificateChain getTrustedIssuers();

	/**
	 * @param trustedIssuers Issuer certificate chain
	 */
	public abstract void setTrustedIssuers(CertificateChain trustedIssuers);

	/**
	 * @return the crl
	 */
	public abstract CertificateRevocationList getCrl();

	/**
	 * @param crl the crl to set
	 */
	public abstract void setCrl(CertificateRevocationList crl);

	/**
	 * @return the signerPublicKey
	 */
	public abstract List<CertificateInterface> getSignerPublicKey();

	/**
	 * @param signerPublicKey the signerPublicKey to set
	 */
	public abstract void setSignerPublicKey(List<CertificateInterface> signerPublicKey);

}