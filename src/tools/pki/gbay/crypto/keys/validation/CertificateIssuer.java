
package tools.pki.gbay.crypto.keys.validation;

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import tools.pki.gbay.configuration.PropertyFileConfiguration;
import tools.pki.gbay.crypto.keys.CertificateValiditor;
import tools.pki.gbay.errors.GbayCryptoException;

import org.apache.log4j.Logger;


/**
 * Representing a CA
 * @author farhang
 *
 */
public class CertificateIssuer extends CertificateValiditor{
	Logger log = Logger.getLogger(CertificateIssuer.class);


	/**
	 * generate certificate issuer
	 * @param name name of issuer (as appeared in DN or a part of DN)
	 * @param fileaddress address of CA cert file
	 * @param certificate {@link X509Certificate} of the issuer
	 * @throws NoSuchAlgorithmException 
	 * @throws CertificateEncodingException 
	 * @throws GbayCryptoException 
	 */
	public CertificateIssuer(String name, X509Certificate certificates) throws CertificateEncodingException, NoSuchAlgorithmException, GbayCryptoException {
		super(certificates);
		log.debug("Certificate issuer is constracting " + name);
		this.name = name;
		this.hascert = true;
	}
	/**
	 * Generate certificate issuers with their name and cer file
	 * @param name  name of issuer (as appeared in DN or a part of DN)
	 * @param fileaddress address of CA cert file
	 * @throws GbayCryptoException 
	 */
	public CertificateIssuer(String name, File fileaddress) throws GbayCryptoException {
		super(fileaddress);
		log.debug(PropertyFileConfiguration.StarLine+"Issuer for "+name+" has been created from : " + fileaddress.getAbsolutePath());
		log.debug("Root cert subjectDN : " +this.getSubjectDN()+PropertyFileConfiguration.StarLine);
		this.name = name;
		this.hascert = true;
	}
	
	
	
	/**
	 * Generate certificate issuer just with it's name <br> Useful for issuers that their root certificate is not available
	 * @param name name of issuer
	 */
	public CertificateIssuer(String name) {
	super();
		this.name = name;
		this.hascert = false;
	}
	
  
	
	/**
	 * Get name of issuer
	 * @return name of issuer
	 */
	public String getName() {
		return name;
	}
	/**
	 * Set name of issuer
	 * @param name name of issuer
	 */
	public void setName(String name) {
		this.name = name;
	}
	/**
	 * Get address of CA cert file
	 * @return address of CA cert file
	 * @throws GbayCryptoException 
	 */

	@Override
	public void setFileAddress(File fileAddress) throws GbayCryptoException {
		super.setFileAddress(fileAddress);
		setHascert();
	}
	
	
	private String name;
	
	/**
	 * Get {@link X509Certificate} of the issuer
	 * @return {@link X509Certificate} of the issuer
	 */
	public X509Certificate getCertificates() {
		return certificates;
	}
	/**
	 * Set {@link X509Certificate} of the issuer
	 * @param certificate {@link X509Certificate} of the issuer
	 */
	public void setCertificates(X509Certificate certificates) {
		setHascert();
		this.certificates = certificates;
	}
	private X509Certificate certificates;
	
	private boolean hascert;
	/**
	 * Indicates if the root certificate of issuer is available or not 
	 * @return true if either certificate path or {@link X509Certificate} of root cert is specified
	 */
	public boolean hasCert() {
		return hascert;
	}
	
	/**
	 * Sets the certificate validity, 
	 * @param hascert
	 */
	private void setHascert() {
		this.hascert = true;
	}
	

}
