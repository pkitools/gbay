package tools.pki.gbay.crypto.provider;

import org.bouncycastle.cms.CMSSignedData;

import tools.pki.gbay.crypto.texts.EncryptedText;
import tools.pki.gbay.crypto.texts.PlainText;
import tools.pki.gbay.crypto.texts.SignedText;
import tools.pki.gbay.crypto.texts.VerificationInterface;
import tools.pki.gbay.errors.CryptoException;

/**
 * Any Class which is providing cryptography operations (Like P12 files / SmartCards or even AES)
 * @author Android
 *
 */
public interface CryptoServiceProvider {
	/**
	 * @return the type
	 */
	public Type getType();
	/**
	 * @param text
	 * @return Signature
	 * @throws CryptoException
	 */
	public SignedText sign(PlainText text) throws CryptoException ;	
	/**
	 * @param text
	 * @return Encrypted text
	 * @throws CryptoException
	 */
	public EncryptedText encrypt(PlainText text) throws CryptoException;
	/**
	 * @param text
	 * @param originalText
	 * @return verification result
	 * @throws CryptoException
	 */
	public VerificationInterface verify(SignedText text, PlainText originalText) throws CryptoException;
	
}
