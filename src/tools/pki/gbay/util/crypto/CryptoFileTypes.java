package tools.pki.gbay.util.crypto;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * CryptoFileTypes. Enum constant names are compatible with JCA names.
 * 
 * @see <a href="http://download.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html">JCA
 *      Standard Names</a>
 */
public enum CryptoFileTypes 
{
	PKCS12("PKCS #12", true, new String[] { "p12", "pfx" }),
	CERTIFICATE("Public Key Certs", false,  new String[0]);
	

	/** Keystore "pretty" name */
	private final String prettyName;

	/** Whether file needs passwords */
	private final boolean needPasswordToOpen;

	/** Associated filename extensions */
	private final Set<String> filenameExtensions;

	/**
	 * Construct a CryptoFileTypes. Private to prevent construction from outside this class.
	 * 
	 * @param sType Keystore publicKeyType
	 * @param supportsCreationDates Whether the keystore supports creation dates
	 * @param filenameExtensions associated filename extensions
	 */
	private CryptoFileTypes(String prettyName, boolean entryPasswordSupported,
	    String[] filenameExtensions)
	{
		this.prettyName = prettyName;
		this.needPasswordToOpen = entryPasswordSupported;
		switch (filenameExtensions.length)
		{
			case 0:
				this.filenameExtensions = Collections.emptySet();
				break;
			case 1:
				this.filenameExtensions = Collections.singleton(filenameExtensions[0]);
				break;
			default:
				LinkedHashSet<String> exts = new LinkedHashSet<String>(filenameExtensions.length);
				Collections.addAll(exts, filenameExtensions);
				this.filenameExtensions = Collections.unmodifiableSet(exts);
		}
	}


	/**
	 * Does the file needs passwords for entries?
	 * 
	 * @return true if entry passwords are supported, false otherwise
	 */
	public boolean isEntryPasswordSupported()
	{
		return needPasswordToOpen;
	}

	/**
	 * Common filename extensions associated with this publicKeyType.
	 * 
	 * @return filename extensions (without leading dot, in lower case), empty if not applicable
	 */
	public Set<String> getFilenameExtensions()
	{
		return filenameExtensions;
	}

	/**
	 * Return string representation of keystore publicKeyType.
	 * 
	 * @return String representation of a keystore publicKeyType
	 */
	@Override
	public String toString()
	{
		return prettyName;
	}

	/**
	 * Get set of all known keystore filename extensions.
	 * 
	 * @return
	 */
	public static Set<String> getKeyStoreFilenameExtensions()
	{
		HashSet<String> exts = new HashSet<String>();
		for (CryptoFileTypes ksType : values())
		{
			for (String ext : ksType.getFilenameExtensions())
			{
				exts.add(ext);
			}
		}
		return exts;
	}
}
