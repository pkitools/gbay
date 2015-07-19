package tools.pki.gbay.errors;

import java.awt.Component;
import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import javax.swing.JOptionPane;

import org.apache.log4j.Logger;

public class CryptoError {
	private static ClassLoader loader;
	private static Logger log = Logger.getLogger(CryptoError.class);
	private String title;
	private String description;
	private Component handler;
	private String variable1;
	private String variable2;
	private String variable3;
	private ErrorLevel messageType;
	private int[] debugPeriod = {8000,9000};
	public static final GlobalErrorCode[] INFO_MESSAGES = new GlobalErrorCode[] {GlobalErrorCode.TXN_SUCCESS,GlobalErrorCode.CERT_EXIST};
	public static final GlobalErrorCode[] WARNING_MESSAGES = new GlobalErrorCode[] {GlobalErrorCode.CERT_EXIST,GlobalErrorCode.REQ_PARAMETER_WARNING,GlobalErrorCode.ENTITY_UPDATE_NEEDED};
	private static final MessageFormat FORMATTER = new MessageFormat("");
	private static final String SUFFIX = ".properties";
	private static final boolean THROW_ON_LOAD_FAILURE = false;
	private GlobalErrorCode error;
	private String message;
	private ResourceBundle englishStrings;


	
	
	
	
	
  /**
	 * @return the resourceBoundler
	 */
	private static ResourceBundle loadBundle() {
	//	try {
		
		String name = Configuration.Error_PROPERTY_FILE ;
		if (Configuration.Error_PROPERTY_FILE == null )
			throw new IllegalArgumentException("null input: name");

		if (Configuration.Error_PROPERTY_FILE.startsWith("/"))
			name = name.substring(1);

	if (name.endsWith(SUFFIX))
			name = name.substring(0, name.length() - SUFFIX.length());

		InputStream in = null;
		
		//	return new File();
		try {
			String address = CryptoError.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();

			//return new File();
			
			log.debug("Name : " + address);
			File propFile = new File(address+ name + SUFFIX);

			if (propFile.exists()){
		

				log.info("Property file is detected");

//				in = new FileInputStream(propFile);
			//	URL[] urls = {propFile.toURI().toURL()};
				//ClassLoader loader = new URLClassLoader(urls);
				URL[] urls = {new File(address).toURI().toURL()};
				 loader = new URLClassLoader(urls);
				ResourceBundle bundle = ResourceBundle.getBundle(name, Configuration.local, loader);


				return  bundle;
			}
			else{
				log.debug("check loader" + name);
			if (loader == null){
				loader = ClassLoaderResolver.getClassLoader(1);
			}
								name = name.replace('/', '.');


				log.debug(name + "  |  "+loader + " " + Configuration.local );
				// throws MissingResourceException on lookup failures:
				return  ResourceBundle.getBundle(name,
						Configuration.local, loader);

			}
		} catch (Exception e) {

			log.error(e);
			if (THROW_ON_LOAD_FAILURE) {
				throw new IllegalArgumentException("could not load ["
						+ name
						+ "]" 
						+ e.getMessage()
						);
			}

		} finally {
			if (in != null)
				try {
					in.close();
				} catch (Throwable ignore) {
				}
		}

		if (THROW_ON_LOAD_FAILURE) {
			throw new IllegalArgumentException("could not load ["
					+ name
					+ "]"
					);
		}
		return null;

	//	return result;

		
//		return	ResourceBundle.getBundle(Configuration.Error_PROPERTY_FILE, Configuration.local, ClassLoaderResolver.getClassLoader());
//			return new PropertyResourceBundle(is);
	
	}

	/**Get the message description if it is found
	 * @return the description
	 */
	public String getDescription() {
		return description;
	}
	public void setVariables (String param0,String param1,String param2){
		this.variable1 = param0;
		this.variable2 = param1;
		this.variable3 = param2;
	}

	// //////////////////////////////////////////////////////////////////////////
	//
	// Constructor
	//
	// //////////////////////////////////////////////////////////////////////////


	private String getString(String key, Object[] args) {
		try {
			FORMATTER.applyPattern(englishStrings.getString(key));
			return FORMATTER.format(args);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}

	/**
	 * Set the error and contents of it
	 * @param err GlobalErrorCode {@link GlobalErrorCode}
	 * @param param0 if your error need some texts inside of it.
	 */
	public void setError(GlobalErrorCode err, String param0 , String param1 , String param2) {
		//loadBundle();
		setVariables(param0, param1, param2);
		error = err;
		setMessage(getString(err.name(), variable1,variable2,variable3));	
		this.variable1 = param0;
		description = getString(err.name() + "." + Configuration.DESC_POSTFIX);
		getType(err);
	}
	
	

	public void setError(int errcode, Component handler) {
		setError(errcode);
		setHandler(handler);
	}



	

	// //////////////////////////////////////////////////////////////////////////
	//
	// Bundle access
	//
	// //////////////////////////////////////////////////////////////////////////
//	private String BUNDLE_ERROR = "tools.pki.gbay.errors.errors";
  
//	private static final MessageFormat FORMATTER = new MessageFormat("");

	/**
	 * @return the title
	 */
	public String getTitle() {
		return title;
	}

	/**
	 * @param title
	 *            the title to set
	 */
	public void setTitle(String title) {
		this.title = title;
	}


	// //////////////////////////////////////////////////////////////////////////
	//
	// Strings access
	//
	// //////////////////////////////////////////////////////////////////////////
	public String getString(String key) {
		// loadBundle();
		try {
			return englishStrings.getString(key);
		} catch (MissingResourceException e) {
			return "!" + key + "!";
		}
	}
/*
	public String getString(String key, Object[] args) {
	try {
			if (args!=null && args.length >0){
				ResourceBundle bundle = Beans.isDesignTime() ? loadBundle() : RESOURCE_BUNDLE;

			FORMATTER.applyPattern(bundle.getString(key));
			return FORMATTER.format(args);
			}
			else{
				ResourceBundle bundle = Beans.isDesignTime() ? loadBundle() : RESOURCE_BUNDLE;

				return bundle.getString(key);
			}
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}
	*/
	public  String getString(String key, String arg0, String arg1) {
		if (arg0!=null && arg1!=null)			
			return getString(key, new Object[] {arg0, arg1});
		else{
			return getString(key,arg0);
		}
	}

	public  String getString(String key, String arg0, String arg1, String arg2) {
		if (arg0!=null && arg1!=null &&arg2 !=null)
		return getString(key, new Object[] {arg0, arg1, arg2});
		else 
			return getString(key,arg0, arg1);
		
	}

	public String getString(String key, String arg0) {
		if (arg0 !=null)
		return getString(key, new Object[] { arg0 });
		else {
			return getString(key);
		}
	}
	
	/**
	 * Show a Swing Option Pane with the error's detail
	 * @param parentComponent
	 */
	public void showMessage(Component parentComponent) {
		JOptionPane.showMessageDialog(parentComponent, message, title,
				errorLevelToInt(messageType));
	}

	public void showMessage() {
		JOptionPane.showMessageDialog(handler, message, title,
				errorLevelToInt(messageType));
	}

	protected int errorLevelToInt(ErrorLevel level) {
		int type = 0;
		if (level == ErrorLevel.ERROR) {
			type = JOptionPane.ERROR_MESSAGE;
		} else if (level == ErrorLevel.WARNING)
			type = JOptionPane.WARNING_MESSAGE;
		else if (level == ErrorLevel.INFO)
			type = JOptionPane.INFORMATION_MESSAGE;
		else if (level == ErrorLevel.CONFIRMATION)
			type = JOptionPane.QUESTION_MESSAGE;
		return type;
	}
	/**
	 * @return the handler
	 */
	public Component getHandler() {
		
		return handler;
	}

	/**
	 * @param handler
	 *            the handler to set
	 */
	public void setHandler(Component handler) {
		this.handler = handler;
	}

	
	/**
	 * @return the messageType
	 */
	public ErrorLevel getMessageType() {
		return messageType;
	}

	/**
	 * @param messageType
	 *            the messageType to set
	 */
	public void setMessageType(ErrorLevel type) {
		this.messageType = type;
	}


	/**
	 * @return the message
	 */
	public String getMessage() {
		return message;
	}

	/**
	 * @param message
	 *            the message to set
	 */
	public void setMessage(String message) {
		this.message = message;
	}
	

	/**
	 * @return the error
	 */
	public int getErrorCode() {
		return error.id;
	}
	
	/**
	 * @return the error
	 */
	public GlobalErrorCode getError() {
		return error;
	}


	/**
	 * @param error
	 *            the error to set
	 */
	public void setError(int globalErrorCode) {
		error = GlobalErrorCode.GetError(globalErrorCode);
		message = this.getString(error.name());
		getType(error);
	}
	


	public ErrorLevel getType(GlobalErrorCode error) {
		if (Arrays.asList(INFO_MESSAGES).contains(error))
		{	messageType = ErrorLevel.INFO;
			title = getString("SUCCESS");
		}
		 else if (Arrays.asList(WARNING_MESSAGES).contains(error)) {
			messageType = ErrorLevel.WARNING;
			title = getString("WARNING");

		} 
		 else if (error.id >= debugPeriod[0] && error.id <= debugPeriod[1]){
			 messageType = ErrorLevel.DEBUG;
		 }
		 else {
			messageType = ErrorLevel.ERROR;
			title = getString("ERROR");
		}
		return messageType;
	}
	
	public CryptoError(GlobalErrorCode err, String param0, String param1, String param2, ErrorLevel errorLevel) {
		load();
		setVariables(param0, param1, param2);
		setError(err, param0 , param1,param2);
		if (errorLevel == null){
			errorLevel = getType(err);
		}
		else{
			setMessageType(errorLevel);
		}
	}
	
	public CryptoError(GlobalErrorCode err) {
		this(err, null, null, null, null);
	}
	
	public CryptoError(String message){
		load();
		this.error = GlobalErrorCode.TXN_FAIL;
		this.message = message;
		this.description = getString(error.name());
	}



	public CryptoError(int globalErrorCode) {
		this(GlobalErrorCode.GetError(globalErrorCode));
	}



	public CryptoError(GlobalErrorCode error, String string, String string2) {
		this(error,string,string2,null, null);
	}



	public CryptoError(GlobalErrorCode error, String string) {
		this(error,string,null,null, null);

	}
	
	@Override 
	public String toString() {
		return getMessage();
	};
	
	private void load(){
//	if (englishStrings==null)
		englishStrings = loadBundle();

    }

	
}