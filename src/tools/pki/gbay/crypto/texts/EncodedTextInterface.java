package tools.pki.gbay.crypto.texts;

import java.io.ByteArrayInputStream;

public interface EncodedTextInterface {

	/**
	 * Decode base64
	 * @return plain text as byte array
	 */
	public abstract byte[] decode();

	/**
	 * String representative of base64 encoded text
	 */
	public abstract String toString();

	/**
	 * Get encoded bytes
	 * @return base64 encoded value as byte array
	 */
	public abstract byte[] toByte();

	/**
	 * Get encoded inputstream
	 * @return {@link ByteArrayInputStream} of encoded value
	 */
	public abstract ByteArrayInputStream toBIS();
	
	

	public abstract Base64 toBase64();

}