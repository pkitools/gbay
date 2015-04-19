/**
 * For more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package tools.pki.gbay.crypto.keys.validation;


import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import tools.pki.ace.webservices.WebService;
import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.GbayCryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;

import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;




public final class CertificateRevocationList {
	X509CRL crl;
	boolean isRevoked;
    /**
     * Extracts the CRL distribution points from the certificate (if available)
     * and checks the certificate revocation status against the CRLs coming from
     * the distribution points. Supports HTTP, HTTPS, FTP and LDAP based URLs.
     * 
     * @param cert
     *            the certificate to be checked for revocation
     * @throws CertificateException 
     * @throws CRLException 
     * @throws CertificateVerificationException
     *             if the certificate is revoked
     */
	
	Logger logger = Logger.getLogger(CertificateRevocationList.class);

    
    public CertificateRevocationList(byte[] crlbyte) throws CRLException, CertificateException {
    	logger.info("Setting CRL...");   
    	this.crl = fromByteArray(crlbyte);
    }
 
    public CertificateRevocationList(X509CRL crl){
    	logger.info("Setting CRL...");
    	this.crl = crl;
    }
  
    public CertificateRevocationList(String crlURL) throws CertificateException, CRLException, IOException, GbayCryptoException, NamingException {
		logger.info("Getting CRL from "+ crlURL);
    	this.crl = downloadCRL(crlURL);
	}
    
   public CertificateRevocationList(X509Certificate certFromFile) throws GbayCryptoException{
	   logger.info("Getting cert from file");
	   List<String> crlList;
	try {
		crlList = getCrlDistributionPoints(certFromFile);
		logger.debug(crlList.size() + " Distribution Point are found");
	if (crlList != null){
		for (String s : crlList){
			logger.info("Downloading crl from " + s);
			this.crl = downloadCRL(s);
			return;
		}
	}
	} catch (CertificateParsingException e) {
	throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT));
	} catch (IOException e) {
		throw new GbayCryptoException(new CryptoError(GlobalErrorCode.FILE_IO_ERROR));
	} catch (CertificateException e) {
		throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT),e);
	} catch (CRLException e) {
		throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT),e);

	} catch (GbayCryptoException e) {
	throw e;
	} catch (NamingException e) {
		throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT),e);

	}

//	this.crl = downloadCRL(crlURL);
		

}

public boolean isRevoked(X509Certificate cert) throws GbayCryptoException{
	   if (cert!=null)
	   return crl.isRevoked(cert);
	   else {
		   throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_NOT_FOUND));
		   }
   }
    
    

    /**
     * Downloads CRL from given URL. Supports http, https, ftp and ldap based
     * URLs.
     */
    private static X509CRL downloadCRL(String crlURL) throws IOException,
            CertificateException, CRLException,
            GbayCryptoException, NamingException {
        if (crlURL.startsWith("http://") || crlURL.startsWith("https://")
                || crlURL.startsWith("ftp://")) {
            return downloadCRLFromWeb(crlURL);
        } else if (crlURL.startsWith("ldap://")) {
            return downloadCRLFromLDAP(crlURL);
        } else {
            throw new GbayCryptoException(
                    "Can not download CRL from certificate "
                            + "distribution point: " + crlURL);
        }
    }

    /**
     * Downloads a CRL from given LDAP url, e.g.
     * ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
     * @throws IOException 
     */
    @SuppressWarnings("rawtypes")
	private static X509CRL downloadCRLFromLDAP(String ldapURL) throws CertificateException, 
    NamingException, CRLException,
    GbayCryptoException, IOException {
        Map<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY,
                "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapURL);

        DirContext ctx = new InitialDirContext((Hashtable)env);
        Attributes avals = ctx.getAttributes("");
        Attribute aval = avals.get("certificateRevocationList;binary");
        byte[] val = (byte[]) aval.get();
        if ((val == null) || (val.length == 0)) {
            throw new GbayCryptoException(
                    "Can not download CRL from: " + ldapURL);
        } else {
        	
        	return fromByteArray(val);
	
        }
    }

    /**
     * Downloads a CRL from given HTTP/HTTPS/FTP URL, e.g.
     * http://crl.pki.tools/crl/identity-ca.crl
     * @throws CertificateException 
     * @throws IOException 
     * @throws MalformedURLException 
     * @throws CRLException 
     */
    private static X509CRL downloadCRLFromWeb(String crlURL) throws CertificateException, MalformedURLException, IOException, CRLException  {
       	InputStream dl = new URL(crlURL).openConnection().getInputStream();
		byte[] data = IOUtils.toByteArray(dl);
   
    	return fromByteArray(data);
    	
         
    
    	/*
    	byte[] buf = null;
    	try {
    	    buf = new byte[is.available()];
    	    while (is.read(buf) != -1) {
    	    }
    	} catch (Exception e) {
    	    System.out.println("Got exception while is -> bytearr conversion: " + e);
    	}
    	PlainText pt= new PlainText(buf);
    	Base64 b64 = new Base64(new String(buf));
    	System.err.println(new String(b64.decode()));
    	System.out.println(pt.toHexadecimalString());
         try{   
       Files.copy(is, new File("a4.crl").toPath()); 
         }
         catch(IOException e){
        	 System.out.println(e.getMessage());
         }
			X509CRL crl = null;
			CertificateFactory factory = null;
			factory = CertificateFactory.getInstance("X509");

			crl = (X509CRL) factory.generateCRL(new ByteArrayInputStream(
					b64.decode()));
       // 	 is.close();
        	return crl;
 //       } finally {
           
    */
    }

    /**
     * Extracts all CRL distribution point URLs from the
     * "CRL Distribution Point" extension in a X.509 certificate. If CRL
     * distribution point extension is unavailable, returns an empty list.
     */
    public static List<String> 
    getCrlDistributionPoints(X509Certificate cert) throws CertificateParsingException, IOException {
        byte[] crldpExt = cert
                .getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (crldpExt == null) {
            return new ArrayList<String>();
        }
        ASN1InputStream oAsnInStream = new ASN1InputStream(
                new ByteArrayInputStream(crldpExt));
        ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
        DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
        byte[] crldpExtOctets = dosCrlDP.getOctets();
        ASN1InputStream oAsnInStream2 = new ASN1InputStream(
                new ByteArrayInputStream(crldpExtOctets));
        ASN1Primitive derObj2 = oAsnInStream2.readObject();
        CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);
        List<String> crlUrls = new ArrayList<String>();
        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            DistributionPointName dpn = dp.getDistributionPoint();
            // Look for URIs in fullName
            if (dpn != null
                && dpn.getType() == DistributionPointName.FULL_NAME) {
                GeneralName[] genNames = GeneralNames.getInstance(
                        dpn.getName()).getNames();
                // Look for an URI
                for (int j = 0; j < genNames.length; j++) {
                    if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
                        String url = DERIA5String.getInstance(
                                genNames[j].getName()).getString();
                       System.out.println("URL : " + url);
                        crlUrls.add(url);
                    }
                }
            }
        }
        oAsnInStream.close();
        oAsnInStream2.close();
        return crlUrls;
    }
    
    public static X509CRL fromByteArray(byte[] crlbyte) throws CRLException, CertificateException{
			CertificateFactory factory = null;
			factory = CertificateFactory.getInstance("X509");
			if (org.apache.commons.codec.binary.Base64.isBase64(crlbyte))
			return (X509CRL) factory.generateCRL(new Base64InputStream(new ByteArrayInputStream(crlbyte)));
			else
			return (X509CRL) factory.generateCRL(new ByteArrayInputStream(crlbyte));
    }

	/**
	 * @return the crl
	 */
	public X509CRL getCrl() {
		return crl;
	}
	
	public static void main(String[] args) {
		try {
		
			downloadCRLFromLDAP("ldap://ldap.digicert.com.my:389/c=MY");
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CRLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GbayCryptoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static X509CRL openCRLFile(String address) throws CertificateException, IOException, CRLException {
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		InputStream in = new FileInputStream(address);
		byte[] data = IOUtils.toByteArray(in);

		X509CRL crl =null;
		if ( org.apache.commons.codec.binary.Base64.isBase64(data)){
			System.err.println("BASE64");
			crl = (X509CRL) cf.generateCRL(new Base64InputStream(new ByteArrayInputStream(data)));	 
		}
		else{
			System.out.println("no base64");
			crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(data));
		}
return crl;

	}
	public static X509CRL openCRLByte(byte[] data) throws CertificateException, IOException, CRLException {
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		if ( org.apache.commons.codec.binary.Base64.isBase64(data)){
			System.err.println("BASE64");
			return (X509CRL) cf.generateCRL(new Base64InputStream(new ByteArrayInputStream(data)));	 
		}
		else{
			System.out.println("no base64");
			return (X509CRL) cf.generateCRL(new ByteArrayInputStream(data));
		}
	}
	   public static X509CRL  getCrlFromCert(X509Certificate certFromFile) throws IOException, CertificateException, CRLException, NamingException, GbayCryptoException {
		   List<String> crlList;
			crlList = getCrlDistributionPoints(certFromFile);
		if (crlList != null){
			for (String s : crlList){
				return downloadCRL(s);
			}
		}
		return null;
	}


}

