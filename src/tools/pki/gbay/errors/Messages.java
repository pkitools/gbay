package tools.pki.gbay.errors;

import java.beans.Beans;
import java.io.IOException;
import java.io.InputStream;
import java.text.MessageFormat;
import java.util.MissingResourceException;
import java.util.PropertyResourceBundle;
import java.util.ResourceBundle;

public class Messages {
	////////////////////////////////////////////////////////////////////////////
	//
	// Constructor
	//
	////////////////////////////////////////////////////////////////////////////
	private Messages() {
		// do not instantiate
	}
	////////////////////////////////////////////////////////////////////////////
	//
	// Bundle access
	//
	////////////////////////////////////////////////////////////////////////////
	//private static final String BUNDLE_NAME = "tools.pki.gbay.errors.errors"; //$NON-NLS-1$
	private static final ResourceBundle RESOURCE_BUNDLE = loadBundle();
	private static final MessageFormat FORMATTER = new MessageFormat("");

	private static  ResourceBundle loadBundle() {
		InputStream is =  Messages.class.getClassLoader().getResourceAsStream("net/scan/aegis/aeh/errors.properties");
		try {
			return new PropertyResourceBundle(is);
		} catch (IOException e) {
			return null;
		}
	//	return ResourceBundle.getBundle(BUNDLE_NAME);
	}
	////////////////////////////////////////////////////////////////////////////
	//
	// Strings access
	//
	////////////////////////////////////////////////////////////////////////////
	public static String getString(String key, String defaultValue, Boolean isArg) {
		if (!isArg){
		try {
			ResourceBundle bundle = Beans.isDesignTime() ? loadBundle() : RESOURCE_BUNDLE;
			return bundle.getString(key);
		} catch (MissingResourceException e) {
			return defaultValue;
		}
		}
		else{
		   return getString(key,defaultValue);	
		}
		
	}
	
	public static String getString(String key) {
		try {
			ResourceBundle bundle = Beans.isDesignTime() ? loadBundle() : RESOURCE_BUNDLE;
			return bundle.getString(key);
		} catch (MissingResourceException e) {
			return key;
		}
	}
	
	public static String getString(String key, String arg0) {
		return getString(key, new Object[] {arg0});
	}

	public static String getString(String key, String arg0, String arg1) {
		return getString(key, new Object[] {arg0, arg1});
	}

	public static String getString(String key, String arg0, String arg1, String arg2) {
		return getString(key, new Object[] {arg0, arg1, arg2});
	}

	public static String getString(String key, Object[] args) {
		try {
			FORMATTER.applyPattern(RESOURCE_BUNDLE.getString(key));
			return FORMATTER.format(args);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}
}
