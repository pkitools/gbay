package tools.pki.gbay.crypto.texts;

import java.security.cert.X509CRL;
import java.util.HashSet;
import java.util.Set;

import tools.pki.gbay.crypto.keys.CertificateInterface;
import tools.pki.gbay.crypto.keys.CertificateValiditor;
import tools.pki.gbay.crypto.keys.validation.CertificateIssuer;
import tools.pki.gbay.crypto.keys.validation.CertificateRevocationList;

/**
 *
 * @author Araz
 */
public class VerifiedText extends PlainText implements VerificationInterface {

	EncodedTextInterface base64signedValue;
	// CertificateIssuer CACert;
	Set<CertificateValiditor> certificate;
	boolean verified;
	boolean validated;
	boolean revoked;
	X509CRL crl;

	protected VerifiedText(String text) {
		super(text);

	}

	/**
	 * Generate VerifiedText object from signed text and original text
	 * @param text original text
	 * @param signedText Signed text
	 */
	public VerifiedText(String text, SignedTextInterface signedText) {
		super(text);
		this.base64signedValue = signedText.toBase64();
		this.certificate = new HashSet<CertificateValiditor>();
	}

	/**
	 * @param text
	 * @param signedText
	 * @param issuers
	 * @param crl
	 */
	public VerifiedText(String text, SignedTextInterface signedText,
			CertificateIssuer issuers, X509CRL crl) {
		super(text);
		this.base64signedValue = signedText.toBase64();
		if (crl != null)
			this.crl = crl;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * tools.pki.gbay.crypto.texts.VerificationInterface#getBase64signedValue()
	 */
	@Override
	public String getBase64signedValue() {
		return base64signedValue.toString();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * tools.pki.gbay.crypto.texts.VerificationInterface#setBase64signedValue
	 * (tools.pki.gbay.crypto.texts.Base64)
	 */
	@Override
	public void setBase64signedValue(EncodedTextInterface base64signedValue) {
		this.base64signedValue = base64signedValue;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see tools.pki.gbay.crypto.texts.VerificationInterface#isVerified()
	 */
	@Override
	public boolean isVerified() {
		return verified;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * tools.pki.gbay.crypto.texts.VerificationInterface#setVerified(boolean)
	 */
	@Override
	public void setVerified(boolean verified) {
		this.verified = verified;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see tools.pki.gbay.crypto.texts.VerificationInterface#isValidated()
	 */
	@Override
	public boolean isValidated() {
		return validated;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * tools.pki.gbay.crypto.texts.VerificationInterface#isVerifiedAndValidated
	 * ()
	 */
	@Override
	public boolean isPassed() {
		return (verified && validated && certificate.size() > 0);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * tools.pki.gbay.crypto.texts.VerificationInterface#setValidated(boolean)
	 */
	@Override
	public void setValidated(boolean validated) {
		this.validated = validated;
	}

	/**
	 * @param certificates
	 */
	public void setCertificates(Set<CertificateValiditor> certificates) {
		if (certificates instanceof CertificateInterface)
			this.certificate = certificates;
	}

	@Override
	public Set<CertificateValiditor> getCertificates() {
		return certificate;
	}

	/**
	 * @return the certificate
	 */
	public Set<CertificateValiditor> getCertificate() {
		return certificate;
	}

	/**
	 * @param certificate
	 *            the certificate to set
	 */
	public void setCertificate(Set<CertificateValiditor> certificate) {
		this.certificate = certificate;
	}

	/**
	 * @return the CertificateRevocationList
	 */
	public CertificateRevocationList getCrl() {
		if (crl!=null)
		return new CertificateRevocationList(crl);
		return null;
	}

	/**
	 * @param crl
	 *            the crl to set
	 */
	public void setCrl(CertificateRevocationList crl) {
		this.crl = crl.getCrl();
	}

	/**
	 * @return the revoked
	 */
	public boolean isRevoked() {
		return revoked;
	}

	/**
	 * @param revoked
	 *            the revoked to set
	 */
	public void setRevoked(boolean revoked) {
		this.revoked = revoked;
	}

	/**
	 * @param crl
	 *            the crl to set
	 */
	public void setCrl(X509CRL crl) {
		this.crl = crl;
	}

}
