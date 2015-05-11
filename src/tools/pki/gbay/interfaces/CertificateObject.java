
package tools.pki.gbay.interfaces ;
 
import java.io.Serializable; 
  
public class CertificateObject implements Serializable {  
	private static final long serialVersionUID = 1L;
	private String subjectkeyid; 
    private String serialno; 
    private String issuerdn; 
    private String cn; 
    private String subjectdn; 
    private String certificate; 
    private String hashcert;  
    private String validfrom; 
    private String validto;
    private String status; 
	
    private byte[] certList;
    private byte[] crlList;
    private byte[] cacertList;
    
    private String crl; 
    private String issuer;
    private String userid;
    
    private String originalData;
    private String signedData;
    
	public String getSubjectkeyid() {
		return subjectkeyid;
	}
	public void setSubjectkeyid(String subjectkeyid) {
		this.subjectkeyid = subjectkeyid;
	}
	public String getSerialno() {
		return serialno;
	}
	public void setSerialno(String serialno) {
		this.serialno = serialno;
	}
	public String getIssuerdn() {
		return issuerdn;
	}
	public void setIssuerdn(String issuerdn) {
		this.issuerdn = issuerdn;
	}
	public String getCn() {
		return cn;
	}
	public void setCn(String cn) {
		this.cn = cn;
	}
	public String getSubjectdn() {
		return subjectdn;
	}
	public void setSubjectdn(String subjectdn) {
		this.subjectdn = subjectdn;
	}
	public String getCertificate() {
		return certificate;
	}
	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}
	public String getHashcert() {
		return hashcert;
	}
	public void setHashcert(String hashcert) {
		this.hashcert = hashcert;
	}
	public String getValidfrom() {
		return validfrom;
	}
	public void setValidfrom(String validfrom) {
		this.validfrom = validfrom;
	}
	public String getValidto() {
		return validto;
	}
	public void setValidto(String validto) {
		this.validto = validto;
	}
	public String getStatus() {
		return status;
	}
	public void setStatus(String status) {
		this.status = status;
	}
	public byte[] getCertList() {
		return certList;
	}
	public void setCertList(byte[] certList) {
		this.certList = certList;
	}
	public String getCrl() {
		return crl;
	}
	public void setCrl(String crl) {
		this.crl = crl;
	}
	public String getIssuer() {
		return issuer;
	}
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}
	public String getUserid() {
		return userid;
	}
	public void setUserid(String userid) {
		this.userid = userid;
	}
	public byte[] getCrlList() {
		return crlList;
	}
	public void setCrlList(byte[] crlList) {
		this.crlList = crlList;
	}
	public byte[] getCacertList() {
		return cacertList;
	}
	public void setCacertList(byte[] cacertList) {
		this.cacertList = cacertList;
	}
	public String getOriginalData() {
		return originalData;
	}
	public void setOriginalData(String originalData) {
		this.originalData = originalData;
	}
	public String getSignedData() {
		return signedData;
	}
	public void setSignedData(String signedData) {
		this.signedData = signedData;
	} 
   
}