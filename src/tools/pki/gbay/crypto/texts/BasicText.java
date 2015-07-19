
package tools.pki.gbay.crypto.texts;

import java.io.File;

import tools.pki.gbay.errors.CryptoException;
import tools.pki.gbay.util.general.CryptoFile;
import tools.pki.gbay.util.general.FileInterface;


/**
 *
 * @author Araz
 */
public abstract class BasicText {
	/**
	 * This is used for showing porposes
	 */
	private  int hexBytesLength = 16;
   /**
 * @param hexBytesLength number of bytes which a separator will be shown after
 */
public void setHexBytesLength(int hexBytesLength) {
		this.hexBytesLength = hexBytesLength;
	}


	/**
	 * 
	 * @param hexBytesSeprater what to show between separated bytes 
	 */
	public void setHexBytesSeprater(String hexBytesSeprater) {
		this.hexBytesSeprater = hexBytesSeprater;
	}

private  String hexBytesSeprater = " ";
   
	byte[] byteRep;
	/**
	 * Constract the PlainText from a plain non-Encoded String
	 * @param text
	 */
	public BasicText(String text) {
		this.byteRep = text.getBytes();
	//	this.text = text;
	}
	

	/**
	 * Make the text from byte array
	 * @param content
	 */
	public BasicText(byte[] content) {
		this.byteRep = content;
	}

	/**
	 * Convert to base64
	 * @return the base 64 encoded text
	 */
	public EncodedTextInterface toBase64() {
		return new Base64(new String(org.bouncycastle.util.encoders.Base64.encode(byteRep)));
	}

	
	/**
	 * Generate text from encoded base64
	 * @param encodedText
	 */
	public BasicText(EncodedTextInterface encodedText) {
		this.byteRep = encodedText.decode();
	}

	/**
	 * Generate text from file
	 * @param container file
	 * @throws CryptoException if file not found our couldn't be read
	 */
	public BasicText(File container) throws CryptoException {
		FileInterface af = new CryptoFile(container.getAbsolutePath());
		byteRep = af.toByte();
	}

	
	/**
	 * Get the byte array of your text
	 * @return text as bytes
	 */
	public byte[] toByte() {
		return byteRep;
	}
	
	
@Override 
public String toString() {
	return new String(byteRep);
}


/**
 * Format the byte array representative of text to hexadecimal display
 * @return the formatted string
 */
public String toHexadecimalString(){
	return toHexadecimalString(hexBytesSeprater, hexBytesLength);
}


/**
 * Format the byte array representative of text to hexadecimal display, interleaving bytes with a
 * separator string. 
 * @param byteSeparator the string that will separate bytes
 * @param wrapAfter length of bytes
 * @return the formated string
 */
public String toHexadecimalString(String byteSeparator,
		int wrapAfter) {
	int n, x;
	String w = new String();
	String s = new String();

	String separator = null;

	for (n = 0; n < byteRep.length; n++) {
		x = (int) (0x000000FF & byteRep[n]);
		w = Integer.toHexString(x).toUpperCase();
		if (w.length() == 1)
			w = "0" + w;

		if ((n % wrapAfter) == (wrapAfter - 1))
			separator = "\n";
		else
			separator = byteSeparator;

		s = s + w + ((n + 1 == byteRep.length) ? "" : separator);

	} // for
	return s;
}

/**
 * decorate a byte array
 * @param byteRep
 * @param byteSeparator
 * @param wrapAfter
 * @return well formated byte array 
 */
public static String toHexadecimalString(byte[] byteRep, String byteSeparator,
		int wrapAfter) {
	int n, x;
	String w = new String();
	String s = new String();
	
	String separator = null;
	
	for (n = 0; n < byteRep.length; n++) {
		x = (int) (0x000000FF & byteRep[n]);
		w = Integer.toHexString(x).toUpperCase();
		if (w.length() == 1)
			w = "0" + w;
		
		if ((n % wrapAfter) == (wrapAfter - 1))
			separator = "\n";
		else
			separator = byteSeparator;
		
		s = s + w + ((n + 1 == byteRep.length) ? "" : separator);
		
	} // for
	return s;
}

}
