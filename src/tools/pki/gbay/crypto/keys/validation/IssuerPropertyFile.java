package tools.pki.gbay.crypto.keys.validation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Properties;

import tools.pki.gbay.configuration.Configuration;
import tools.pki.gbay.configuration.PropertyHelper;
import tools.pki.gbay.crypto.provider.CaFinderInterface;
import tools.pki.gbay.errors.GbayCryptoException;

import org.apache.log4j.Logger;

public class IssuerPropertyFile  implements CaFinderInterface {
	
	Logger log = Logger.getLogger(IssuerPropertyFile.class);

	
	
	/**
	 * 
	 */
	private HashMap<String,String> CA_ROOT_CERTS;


	
	
	private IssuerPropertyFile(){
	}
	
	
	
	private static Properties constractDefualtProperty(Properties file) throws IOException , FileNotFoundException{
		if (file != null)
		{
			return file;
		}
		else{
			Properties prop = new Properties(); 
			InputStream input = new FileInputStream(Configuration.getDefualtCaListFile());
			prop.load(input);
			return  prop;
		}
	} 
	private  HashMap<String, String> constractDefualtReplacment(HashMap<String, String> replacements){
		if ( replacements == null){
			replacements = new HashMap<String, String>();
			replacements.put("=", "[$eq]");
			replacements.put(" ", "[$es]");
		}
		return replacements;
	}
	
	

	private static IssuerPropertyFile instance;

	/**
	 * This will get the CA certs from a propertifile and if null parameters be passed it will use it's defualt configurations
	 * @param replacements In a property file you might have some replacements by defualt 	"=" is replaced with "[$eq]" and " " with "[$es]".<br> it means instead of searching for space, program will search for [$eq]
	 * @param propFile Property file, if it is null "trust.conf" is used
	 * @return Instance of issuer file
	 * @throws IOException
	 */
		public static IssuerPropertyFile getInstance() throws IOException {
			if (instance == null) {
				System.out.println("Issuer property is null");
				instance = new IssuerPropertyFile();
			}
			return instance;
		}

		/**
		 * This will get the CA certs from a propertifile and if null parameters be passed it will use it's defualt configurations
		 * @param replacements In a property file you might have some replacements by defualt 	"=" is replaced with "[$eq]" and " " with "[$es]".<br> it means instead of searching for space, program will search for [$eq]
		 * @param propFile Property file, if it is null "trust.conf" is used
		 * @return Instance of issuer file
		 * @throws IOException
		 */

		public void initiate(HashMap<String, String> replacements, Properties propertyFile) throws FileNotFoundException, IOException {
			log.debug("Innisiating Issuer property file " + propertyFile.toString());
			PropertyHelper.GetInstance().initiate(constractDefualtReplacment(replacements),constractDefualtProperty(propertyFile));
		}

	
	transient File caFile;


	public File getCARootCert(X509Certificate cert) {
		log.debug("Getting CA Cert file...");
		String caFile = PropertyHelper.GetInstance().getProperty(getSettingIssuerDn(cert.getIssuerDN()
				.toString()));
		if (caFile == null || caFile.isEmpty())
			return null;
		return new File(caFile);
	}
	@Override
	public CertificateIssuer getIssuer(X509Certificate cert) throws GbayCryptoException{
		log.debug("Getting issuer for " + cert.getSubjectDN());
		File caRootCert = getCARootCert(cert);
		if (caRootCert == null){
			return null;
		}
		else
		return new CertificateIssuer(cert.getSubjectDN().toString(),caRootCert);
	}

	private String getSettingIssuerDn(String issuerDn) {
		log.info("Finding proper key in property files ... ");
		return PropertyHelper.GetInstance().replaceValuesWithReplacementKeys(issuerDn);	
	}
	
	
	
	public HashMap<String, String> getAllIssuers(){
      if(CA_ROOT_CERTS == null)
    	CA_ROOT_CERTS=  PropertyHelper.GetInstance().retrieveKeys();
		    return CA_ROOT_CERTS;
    }

}
