package tools.pki.gbay.crypto.texts;

import java.util.List;
import java.util.Set;

import tools.pki.gbay.crypto.keys.CertificateInterface;
import tools.pki.gbay.crypto.keys.validation.CertificateIssuer;
import tools.pki.gbay.crypto.keys.validation.CertificateRevocationList;
import tools.pki.gbay.crypto.provider.CryptoServiceProvider;
import tools.pki.gbay.errors.GbayCryptoException;

public interface SignedTextInterface {

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

	public abstract VerificationInterface verify(CryptoServiceProvider csp)
			throws GbayCryptoException;

	/**
	 * @return the caCert
	 */
	public abstract Set<CertificateIssuer> getTrustedIssuers();

	/**
	 * @param caCert the caCert to set
	 */
	public abstract void setTrustedIssuers(Set<CertificateIssuer> trustedIssuers);

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