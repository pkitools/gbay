package tools.pki.gbay.crypto.texts;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;

import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.CryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;
import tools.pki.gbay.util.general.CryptoFile;
import tools.pki.gbay.util.general.FileInterface;


/**
 * Generates a base64 encoded object
 * @author Araz
 */

public class Base64 implements EncodedTextInterface {
	/**
	 * Symbol that represents the end of an input stream
	 */
	//private static final int END_OF_INPUT = -1;

	/**
	 * A character that is not a valid base 64 character.
	 */
	
	private static final int NON_BASE_64 = -1;

	/**
	 * A character that is not a valid base 64 character.
	 */
	private static final int NON_BASE_64_WHITESPACE = -2;

	/**
	 * A character that is not a valid base 64 character.
	 *
	 *
	 */
	private static final int NON_BASE_64_PADDING = -3;

	
	/**
	 * Table of the sixty-four characters that are used as
	 * the Base64 alphabet: [a-z0-9A-Z+/]
	 */
	protected static final byte[] base64Chars = {
		'A','B','C','D','E','F','G','H',
		'I','J','K','L','M','N','O','P',
		'Q','R','S','T','U','V','W','X',
		'Y','Z','a','b','c','d','e','f',
		'g','h','i','j','k','l','m','n',
		'o','p','q','r','s','t','u','v',
		'w','x','y','z','0','1','2','3',
		'4','5','6','7','8','9','+','/',
	};

	/**
	 * Reverse lookup table for the Base64 alphabet.
	 * reversebase64Chars[byte] gives n for the nth Base64
	 * character or negative if a character is not a Base64 character.
	 *
	 */
	protected static final byte[] reverseBase64Chars = new byte[0x100];
	static {
		// Fill in NON_BASE_64 for all characters to start with
		for (int i=0; i<reverseBase64Chars.length; i++){
			reverseBase64Chars[i] = NON_BASE_64;
		}
		// For characters that are base64Chars, adjust
		// the reverse lookup table.
		for (byte i=0; i < base64Chars.length; i++){
			reverseBase64Chars[base64Chars[i]] = i;
		}
		
		reverseBase64Chars[' '] = NON_BASE_64_WHITESPACE;
		reverseBase64Chars['\n'] = NON_BASE_64_WHITESPACE;
		reverseBase64Chars['\r'] = NON_BASE_64_WHITESPACE;
		reverseBase64Chars['\t'] = NON_BASE_64_WHITESPACE;
		reverseBase64Chars['\f'] = NON_BASE_64_WHITESPACE;
		reverseBase64Chars['='] = NON_BASE_64_PADDING;
	}


	
	byte[] encodedText;
	Logger log = Logger.getLogger(Base64.class);
	/**
	 * If you want to generate a {@link Base64} object from an encoded text you need to use {@link String}  <p>
	 * Otherwise use arrays of {@link Byte}
	 * Generate BASE64 object from a base64 encoded text
	 * @param encodedText base64 encoded String
	 * @see Base64#Base64(byte[])
	 */
	public Base64(String encodedText) {
		this.encodedText = encodedText.getBytes();
	}
	
	/**
	 * To encode a plain inputStream
	 * @param plainInputStream
	 */
	public Base64(InputStream plainInputStream) throws CryptoException {
		log.info("Reading input stream");
    	try {
			byte[] bytes = IOUtils.toByteArray(plainInputStream);
			this.encodedText = org.bouncycastle.util.encoders.Base64.encode(bytes);
    		log.debug("InputStream Encoded");

    	} catch (IOException e1) {
			throw new CryptoException(new CryptoError(GlobalErrorCode.FILE_IO_ERROR));
		}
    	

	}
	
	/**
	 * Load a file into base64 format
	 * @param fileAddress
	 * @throws CryptoException
	 */
	public Base64(File fileAddress) throws CryptoException{
		FileInterface af = new CryptoFile(fileAddress.getAbsolutePath());
		this.encodedText =org.bouncycastle.util.encoders.Base64.encode(af.toByte());
	}
	/**
	 * Encode a byte array to base64
	 * <p><b>Note:</b> If your text is already a base64 encoded text use the constructor with STRING {@link String}</p>
	 * @param bytes plain byte array
	 */
	public Base64(byte[] bytes){
		this.encodedText = org.bouncycastle.util.encoders.Base64.encode(bytes);
	}
	
	/**
	 * Decode the text to plain text
	 * @return
	 */
	@Override
	public byte[] decode(){
		return org.bouncycastle.util.encoders.Base64.decode(encodedText);
	}
	
	public static byte[] decode(String encodedText){
		return org.bouncycastle.util.encoders.Base64.decode(encodedText);
	}

	public static byte[] encode(String plainText){
		return org.bouncycastle.util.encoders.Base64.encode(plainText.getBytes());
	}
	
	
	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.texts.EncodedTextInterface#toString()
	 */

	@Override
	public String toString(){
		return new String(encodedText);
	}
	
	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.texts.EncodedTextInterface#toByte()
	 */
	@Override
	public byte[] toByte(){
		return encodedText;
	}
	
	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.texts.EncodedTextInterface#toBIS()
	 */
	@Override
	public ByteArrayInputStream toBIS(){
		return new ByteArrayInputStream(toByte());
	}
	

	@Override
	public Base64 toBase64(){
		return this;
	}
	
	
	public static boolean isBase64(InputStream in) throws IOException {
		long numBase64Chars = 0;
		int numPadding = 0;
		int read;

		while ((read = in.read()) != -1){
			read = reverseBase64Chars[read];
			if (read == NON_BASE_64){
				return false;
			} else if (read == NON_BASE_64_WHITESPACE){
				// ignore white space
			} else if (read == NON_BASE_64_PADDING){
				numPadding++;
				numBase64Chars++;
			} else if (numPadding > 0){
				return false;
			} else {
				numBase64Chars++;
			}
		}
		if (numBase64Chars == 0) return false;
		if (numBase64Chars % 4 != 0) return false;
		return true;
	}
}
