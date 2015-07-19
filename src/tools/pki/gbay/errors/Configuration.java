package tools.pki.gbay.errors;

import java.util.Locale;
import java.util.ResourceBundle;

public class Configuration {
//    public static final String Error_PROPERTY_FILE = Configuration.class.getPackage().getName() + ".errors";
    protected static final String Error_PROPERTY_FILE = "errors";

    protected static  Locale  local = Locale.US;
	protected static final String DESC_POSTFIX = "detail";

	/**
	 * @return the local
	 */
	public static Locale getLocal() {
		return local;
	}

	/**
	 * @param local the local to set
	 */
	public static void setLocal(Locale local) {
		Configuration.local = local;
	}
    
    
    
//	public static final ResourceBundle RESOURCE_BUNDLE = loadBundle();

  /**
	 * @return the resourceBoundler
	 */
//	private static ResourceBundle loadBundle() {
///		return ResourceBundle.getBundle(Error_PROPERTY_FILE);
//	}
	//public static ResourceBundle getResourceBoundler(){
	/*	
		if (rb!=null)
			return rb;
		else{
			
		rb = ResourceBundle.getBundle(Error_PROPERTY_FILE,Locale.ROOT);
		return rb;
		}
		*/
	//	return RESOURCE_BUNDLE;
//	}
	
	

}
