package tools.pki.gbay.configuration;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.Properties;

import org.apache.log4j.Logger;

import tools.pki.gbay.crypto.keys.validation.IssuerPropertyFile;


/**
 * @author Ashwin Gets System variables that were loaded at server startup from
 *         the server.properties file
 */
public class PropertyLoader {
	Logger log = Logger.getLogger(IssuerPropertyFile.class);

	private static boolean initializedFromFile = false;

	/**
	 * Get the Property From Server.properties. This is used when we want to
	 * read property from file each and every time
	 *
	 * @param key
	 * @return
	 */
	public static String getProperty(String key) {
		Properties props = new Properties();
		InputStream stream = PropertyLoader.class
				.getResourceAsStream("/server.properties");
		try {
			props.load(stream);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return props.getProperty(key);
	}

	/**
	 * This is used when we just want to load all properties loaded and are sure
	 * that those dont change while server is running thereby reducing load of
	 * reading from file
	 *
	 * Get the value of the key passed.
	 *
	 * @param key
	 *            the token
	 * @return the value if there is one, otherwise null
	 */
	public static final String getSystemString(String key) {
		String value = null;
		try {
			value = System.getProperty(key);
		} catch (NullPointerException e) {
			// ignore just return null;
		}
		return value;
	}


	public static final void loadSystemProperties() throws IOException {
		loadSystemProperties("/server.properties");
	}

	/**
	 * Give the classpath qualified name of the filename to load, e.g.
	 *
	 *
	 * /config.properties
	 * 
	 *
	 * @param file
	 *            the classpath qualified filename of the file to load
	 */
	public static final void loadSystemProperties(String file)
			throws IOException {
		Properties props = new Properties();
		InputStream stream = PropertyLoader.class.getResourceAsStream(file);
		props.load(stream);
		Iterator iterator = props.keySet().iterator();
		while (iterator.hasNext()) {
			String key = (String) iterator.next();
			String value = props.getProperty(key);
			System.getProperties().setProperty(key, value);
		}
		initializedFromFile = true;
	}

	/**
	 * Sets the property and returns the previous value
	 *
	 * @param key
	 * @param value
	 */
	public static final String setSystemProperty(String key, String value) {
		if (!initializedFromFile) {
			log.warn("Attempting to set System Property " + key + " to "
					+ value
					+ " but the file System Properties have not yet been read.");
		}
		return System.setProperty(key, value);
	}

	/**
	 * Replaces all config parameters in the string with the actual values.
	 * Parameters are in the form ${PARAM_NAME}. If a parameter tag is
	 * encountered, and the corresponding value cannot be retrieved, an
	 * exception will be generated.
	 */
	public static void resolveParameterTags(StringBuffer sb) {
		int basePos = 0;
		String rstr = sb.toString();
		final String tagStartToken = "${";
		final String tagEndToken = "}";
		int pos = rstr.indexOf(tagStartToken);
		while (pos >= 0) {
			int endPos = rstr.indexOf(tagEndToken, pos);
			if (endPos < 0) {
				String msg = "Parameter tag not closed: " + rstr;
				throw new IllegalArgumentException(msg);
			}
			String pName = rstr.substring(pos + tagStartToken.length(), endPos);
			String parameterValue = getSystemString(pName);
			if (parameterValue == null || "".equals(parameterValue)) {
				String msg = "Missing configuration parameter " + pName
						+ " for tag " + rstr;
				throw new IllegalArgumentException(msg);
			}
			// replace the parameter
			sb.replace(basePos + pos, basePos + endPos + tagEndToken.length(),
					parameterValue);
			// point base position to the rest of the string
			basePos = basePos + pos + parameterValue.length();
			rstr = sb.substring(basePos);
			pos = rstr.indexOf(tagStartToken);
		}
	}


	/**
	 * Gets the boolean value if the string equalsIgnoreCase true, otherwise
	 * false.
	 *
	 * @param key
	 *            the token
	 * @return true if the value is ignorecase true all other values including
	 *         null return false.
	 */
	public static final boolean getBoolean(String key) {
		String token = getSystemString(key);
		if (token == null) {
			return false;
		}
		if (token.equalsIgnoreCase("true")) {
			return true;
		}
		return false;
	}
	
	public static long getLong(String key, long i) {
		String token = getSystemString(key);
		if (token == null) {
			return i;
		}
		return Long.parseLong(token);
	}

	public static int getInt(String key, int i) {
		String token = getSystemString(key);
		if (token == null) {
			return i;
		}
		return Integer.parseInt(token);
	}
}