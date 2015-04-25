package tools.pki.gbay.configuration;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;


public class IssuerPropertyHelper {

	private static IssuerPropertyHelper _instance = null;
	
	public static IssuerPropertyHelper GetInstance(){
		if (_instance == null)
			_instance = new IssuerPropertyHelper();
		return _instance;
	}
	
	/**
	 * 
	 */
	Logger log = Logger.getLogger(IssuerPropertyHelper.class);

	protected Properties property;

	public HashMap<String,String> retrieveKeys(){
		log.debug("Retrieving keys");
		HashMap<String, String> values = new HashMap<String, String>();
		for (final String name:property.stringPropertyNames())
		    values.put(name, property.getProperty(name));
		
		return values;
	} 
	
	protected HashMap<String, String> REPLACEMENT_KEYS_IN_PROPERTIES;

	public void initiate(HashMap<String, String> replacement, Properties propertyFile) throws FileNotFoundException, IOException {
		log.debug("Initiating property helper...");
		this.REPLACEMENT_KEYS_IN_PROPERTIES = replacement;
		log.debug("replacments initiated");
		this.property = propertyFile;
		log.debug("Property object is setted " );
	}

	
	public String replaceValuesWithReplacementKeys(String issuerDn) {
		log.debug("Constract key... for "+issuerDn );
		String result = issuerDn;
		for (Map.Entry<String, String> entry : REPLACEMENT_KEYS_IN_PROPERTIES
				.entrySet()) {
			log.debug("Replacing '" + entry.getKey() + "' with '"+entry.getValue()+"'");
			result = result.replace(entry.getKey(), entry.getValue());
			log.debug("rep: "+result);
		}
		
		log.debug("Result of replacement = " + result);
		return result;
	}


	public String getProperty(String settingIssuerDn) {
		return property.getProperty(settingIssuerDn);
	}
	
	


}
