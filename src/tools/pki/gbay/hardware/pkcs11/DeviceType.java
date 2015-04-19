package tools.pki.gbay.hardware.pkcs11;

public enum DeviceType{
 smartCard(1), secureToken(4), softCert(2),Roaming(3) , None(-1); 
 public final int id;
 private DeviceType(int i){id = i;}
 public boolean Compare(int i){return id == i;}
 
 public static DeviceType GetDevice(int _id)
 {
	 DeviceType[] As = DeviceType.values();
     for(int i = 0; i < As.length; i++)
     {
         if(As[i].Compare(_id))
             return As[i];
     }
     return DeviceType.None;
 }
}
