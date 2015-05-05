package tools.pki.gbay.crypto.provider;

import org.bouncycastle.cms.CMSSignedData;

import tools.pki.gbay.crypto.texts.EncryptedText;
import tools.pki.gbay.crypto.texts.PlainText;
import tools.pki.gbay.crypto.texts.SignedText;
import tools.pki.gbay.crypto.texts.VerificationInterface;
import  tools.pki.gbay.errors.GbayCryptoException;

public interface CryptoServiceProvider {
	/**
	 * @return the type
	 */
	public Type getType();
	public SignedText sign(PlainText text) throws GbayCryptoException ;	
	public EncryptedText encrypt(PlainText text) throws GbayCryptoException;
	public VerificationInterface verify(SignedText text, PlainText originalText) throws GbayCryptoException;
	public CMSSignedData getSignedData() throws GbayCryptoException;
}
