package tools.pki.gbay.crypto.provider;

public enum Type{
 smartCard(1), secureToken(4), softCert(2),Roaming(3) , None(-1); 
 public final int id;
 private Type(int i){id = i;}
 public boolean Compare(int i){return id == i;}
 
 public static String SMART_CARD_TEXT = "smartcard";
 public static String TOKEN_TEXT = "soft";
 public static String SOFT_CERT_TEXT = "smartcard";
 public static String ROAMING_TEXT = "smartcard";
 
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
