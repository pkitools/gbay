package tools.pki.gbay.crypto.provider;

/**
 * Possible cryptography Providers
 * @author Android
 *
 */
public enum Type{
 /**
 * Smart Cards 
 */
smartCard(1), /** PKI tokens
 * 
 */
secureToken(4), /** P12 files in client side
 * 
 */
softCert(2),/**
 * Provide Server side Crypto operations
 */
Roaming(3) , /**
 * None of the above
 */
None(-1); 
 /**
 * ID of the Cryptography provider type
 */
public final int id;
 private Type(int i){id = i;}
 /**
 * @param i
 * @return true if two types are equal
 */
public boolean Compare(int i){return id == i;}
 
 /**
 * Friendly name 
 */
public static String SMART_CARD_TEXT = "smartcard";
/**
* Friendly name 
*/
public static String TOKEN_TEXT = "token";
/**
* Friendly name 
*/ 
public static String SOFT_CERT_TEXT = "soft-certs";
/**
* Friendly name 
*/ 
public static String ROAMING_TEXT = "roaming-certs";
 
 /**
 * @param _id
 * @return Provider type
 */
public static Type GetType(int _id)
 {
	 Type[] As = Type.values();
     for(int i = 0; i < As.length; i++)
     {
         if(As[i].Compare(_id))
             return As[i];
     }
     return Type.None;
 }
 
 /**
 * @param typetext
 * @return provider type
 */
public static Type getType(String typetext){
	 
	 if (typetext.equals(SMART_CARD_TEXT)){
		 return smartCard;
	 }else if (typetext.equals(TOKEN_TEXT)){
		 return secureToken;
	 }else if (typetext.equals(SOFT_CERT_TEXT)){
		 return softCert;
	 }else if (typetext.equals(ROAMING_TEXT)){
		 return Roaming;
	
	 }else {
		 return None;
		 
	 }
 }
 
 
}
