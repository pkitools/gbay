package tools.pki.gbay.util.general;

import java.io.File;
import java.io.IOException;

import tools.pki.gbay.crypto.texts.PlainText;

public interface FileInterface {

	public abstract void write() throws IOException;

	/**
	 * @return the content
	 */
	public abstract byte[] toByte();

	/**
	 * @return the content
	 */
	public abstract PlainText getContent();

	/**
	 * @return the file
	 */
	public abstract File getFile();

	/**
	 * @return the path
	 */
	public abstract String getPath();

}