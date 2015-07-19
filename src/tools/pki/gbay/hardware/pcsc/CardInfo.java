/**
 *	GBay Hardware Devices - a token and smart card managment solution (library)
 *	Copyright (c) 2014 Araz Farhang - www.pki.tools
 *	
 *	This API is intended to be used by other aegis applications
 *
 *	This program is distributed in the hope that it will be useful.
 *	
 */

/*
 * $Date: 2004/12/27 11:14:32 $
 */
package tools.pki.gbay.hardware.pcsc;

import java.util.Hashtable;

/**
 * Stores informations about a card.
 * 
 * @author Araz Farhang
 *
 */

public class CardInfo {
    private Hashtable infos = new Hashtable();

    /**
     * Adds the given attribute with corresponding value.
     * 
     * @param attribute key for retrieving the information.
     * @param value information to store.
     */
    public void addProperty(String attribute, Object value) {
     
    	infos.put(attribute, value);
    }

    /**
     * Retrieves the value for the given attribute.
     * 
     * @param attribute key to search.
     * @return the value for the given attribute, <code>null</code> if not found.
     */
    public String getProperty(String attribute) {
        return (String) infos.get(attribute);
    }
    
    /**
     * description of device
     * @return description of device
     */
    public String getDescription(){
    	return getProperty("description");
    }
    
    
    /**
     * Address of device's library (cryptoki driver)
     * @return Address of PKCS#11 library
     */
    public String getLib(){
    	return getProperty("lib");
    }
    
    
    /**
     * ATTR of device if it is applicable
     * @return ATTR of device
     */
    public String getATR(){
    	return getProperty("atr");
    }
    
    @Override
    public String toString() {
    	return getProperty("description");
    }

}