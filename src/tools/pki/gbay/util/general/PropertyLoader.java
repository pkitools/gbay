/*
 * GBAy Crypto API
 * Copyright (c) 2014, PKI.Tools All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package tools.pki.gbay.util.general;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Locale;
import java.util.Properties;
import java.util.ResourceBundle;

import org.apache.log4j.Logger;

// TODO: Auto-generated Javadoc
// ----------------------------------------------------------------------------
/**
 * A simple class for loading java.util.Properties backed by .properties files
 * deployed as classpath resources.
 * 
 */
public abstract class PropertyLoader {

	// public: ................................................................

	/**
	 * Looks up a resource named 'name' in the classpath. The resource must map
	 * to a file with .properties extention. The name is assumed to be absolute
	 * and can use either "/" or "." for package segment separation with an
	 * optional leading "/" and optional ".properties" suffix. Thus, the
	 * following names refer to the same resource:
	 * 
	 * <pre>
	 * some.pkg.Resource
	 * some.pkg.Resource.properties
	 * some/pkg/Resource
	 * some/pkg/Resource.properties
	 * /some/pkg/Resource
	 * /some/pkg/Resource.properties
	 * </pre>
	 *
	 * @param name            classpath resource name [may not be null]
	 * @param loader            classloader through which to load the resource [null is
	 *            equivalent to the application loader]
	 * @return resource converted to java.util.Properties [may be null if the
	 *         resource was not found and THROW_ON_LOAD_FAILURE is false]
	 */
	public static Properties loadProperties(String name, ClassLoader loader) {
		if (name == null )
			throw new IllegalArgumentException("null input: name");

		if (name.startsWith("/"))
			name = name.substring(1);

		if (name.endsWith(SUFFIX))
			name = name.substring(0, name.length() - SUFFIX.length());

		Properties result = null;

		InputStream in = null;
		File propFile = new File(name);

		try {
			if (propFile.exists()){
				in = new FileInputStream(propFile);
			// load a properties file
			result = new Properties();
				result.load(in);
			if (saveInSystem) {
				Iterator<Object> iterator = result.keySet().iterator();
				while (iterator.hasNext()) {
					String key = (String) iterator.next();
					String value = result.getProperty(key);
					System.getProperties().setProperty(key, value);
				}
			}
			}
			else{
			if (loader == null)
				loader = ClassLoaderResolver.getClassLoader();

			if (LOAD_AS_RESOURCE_BUNDLE) {
				name = name.replace('/', '.');

				// throws MissingResourceException on lookup failures:
				final ResourceBundle rb = ResourceBundle.getBundle(name,
						Locale.getDefault(), loader);

				result = new Properties();
				for (Enumeration<String> keys = rb.getKeys(); keys
						.hasMoreElements();) {
					final String key = (String) keys.nextElement();
					final String value = rb.getString(key);
					if (saveInSystem)
						System.getProperties().setProperty(key, value);

					result.put(key, value);
				}
			} else {
				name = name.replace('.', '/');

				if (!name.endsWith(SUFFIX))
					name = name.concat(SUFFIX);

				// returns null on lookup failures:
				in = loader.getResourceAsStream(name);
				if (in != null) {
					result = new Properties();
					result.load(in); // can throw IOException
					if (saveInSystem) {
						Iterator<Object> iterator = result.keySet().iterator();
						while (iterator.hasNext()) {
							String key = (String) iterator.next();
							String value = result.getProperty(key);
							System.getProperties().setProperty(key, value);
						}
					}
				}
			}
			}
		} catch (Exception e) {
			result = null;
		} finally {
			if (in != null)
				try {
					in.close();
				} catch (Throwable ignore) {
				}
		}

		if (THROW_ON_LOAD_FAILURE && (result == null)) {
			throw new IllegalArgumentException("could not load ["
					+ name
					+ "]"
					+ " as "
					+ (LOAD_AS_RESOURCE_BUNDLE ? "a resource bundle"
							: "a classloader resource"));
		}

		return result;
	}

	/**
	 * A convenience overload of {@link #loadProperties(String, ClassLoader)}
	 * that uses gbay class loader. {@link ClassLoaderResolver#getClassLoader()}
	 *
	 * @param name the name
	 * @return the properties
	 */
	public static Properties loadProperties(final String name) {
		return loadProperties(name, ClassLoaderResolver.getClassLoader());
	}
	
	/**
	 * A convenience overload of {@link #loadProperties(String)}
	 * that uses the file address. {@link #propertyFileAddress}
	 *
	 * @return the properties
	 */
	public static Properties loadProperties() {
		return loadProperties(propertyFileAddress);
	}


	/**
	 * Get the Property From Server.properties. This is used when we want to
	 * read property from file each and every time
	 *
	 * @param key the key
	 * @return the property string
	 */
	public static final String getPropertyString(String key) {
		Properties props = new Properties();
		props = loadProperties(propertyFileAddress);
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

			if (THROW_ON_LOAD_FAILURE)
				throw e;
		}
		return value;
	}

	/**
	 * Sets the property and returns the previous value.
	 *
	 * @param key the key
	 * @param value the value
	 * @return the string
	 */
	public static final String setSystemProperty(String key, String value) {
		if (!saveInSystem) {
			log.warn("Attempting to set System Property " + key + " to "
					+ value
					+ " but the file System Properties have not yet been read.");
		}
		return System.setProperty(key, value);
	}

	/**
	 * Get string value either from System or properties file
	 * {@link #saveInSystem}.
	 *
	 * @param key the key
	 * @return null if not found and value if found
	 */
	public static final String getString(String key) {
		if (saveInSystem)
			return getSystemString(key);
		else
			return getPropertyString(key);
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
		String token = getString(key);
		if (token == null) {
			return false;
		}
		if (token.equalsIgnoreCase("true")) {
			return true;
		}
		return false;
	}

	/**
	 * get a long number from properties.
	 *
	 * @param key            the key to find
	 * @param i            defualt value
	 * @return the long
	 */
	public static long getLong(String key, long i) {
		String token = getString(key);
		if (token == null) {
			return i;
		}
		return Long.parseLong(token);
	}

	/**
	 * Get integer value from property file.
	 *
	 * @param key            the key to find
	 * @param i            defualt value
	 * @return the int
	 */
	public static int getInt(String key, int i) {
		String token = getSystemString(key);
		if (token == null) {
			return i;
		}
		return Integer.parseInt(token);
	}

	/**
	 * Get the file that is in use for reading properties file.
	 *
	 * @return Address of property file
	 */
	public static String getPropertyFile() {
		return propertyFileAddress;
	}

	/**
	 * Checks if is throw on load failure.
	 *
	 * @return true, if checks if is throw on load failure
	 */
	public static boolean isThrowOnLoadFailure() {
		return THROW_ON_LOAD_FAILURE;
	}

	/**
	 * Checks if is load as resource bundle.
	 *
	 * @return true, if checks if is load as resource bundle
	 */
	public static boolean isLoadAsResourceBundle() {
		return LOAD_AS_RESOURCE_BUNDLE;
	}

	/**
	 * Checks if is save in system.
	 *
	 * @return true, if checks if is save in system
	 */
	public static boolean isSaveInSystem() {
		return saveInSystem;
	}

	/**
	 * Set this true if you are sure that property file would not change in run
	 * time, by setting this value application will save all properties in
	 * system variables.
	 *
	 * @param saveInSystem            set true to save in system and decrease the speed by bypassing
	 *            referring to file, false to read values in runtime
	 */
	public static void setSaveInSystem(boolean saveInSystem) {
		PropertyLoader.saveInSystem = saveInSystem;
	}

	/**
	 * Gets the property file address.
	 *
	 * @return the property file address
	 */
	public static String getPropertyFileAddress() {
		return propertyFileAddress;
	}

	/**
	 * Initiate.
	 *
	 * @param propertyAddress the property address
	 * @param saveInSystem the save in system
	 */
	public static void initiate(String propertyAddress, boolean saveInSystem) {
		propertyFileAddress = propertyAddress;
		PropertyLoader.saveInSystem = saveInSystem;

	}

	// protected: .............................................................

	// package: ...............................................................

	// private: ...............................................................
	/** The log. */
	static Logger log = Logger.getLogger(PropertyLoader.class);

	private static String propertyFileAddress = "config.properties";

	private PropertyLoader() {
	} // this class is not extentible

	private static boolean saveInSystem = false;
	private static final boolean THROW_ON_LOAD_FAILURE = true;
	private static final boolean LOAD_AS_RESOURCE_BUNDLE = false;
	private static final String SUFFIX = ".properties";

} // end of class
// ----------------------------------------------------------------------------