
/*
 * GBAy Crypto API
 * Copyright (c) 2014, PKI.Tools All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package tools.pki.gbay.crypto.keys;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.naming.NamingException;
import javax.security.auth.x500.X500Principal;

import tools.pki.gbay.configuration.PropertyFileConfiguration;
import tools.pki.gbay.crypto.keys.validation.CertificateIssuer;
import tools.pki.gbay.crypto.keys.validation.CertificateRevocationList;
import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.CryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;
import tools.pki.gbay.interfaces.SignatureSettingInterface;
import tools.pki.gbay.util.general.Convertors;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import com.google.inject.Inject;

/**
 * The Class StandardCertificate is a normal X509 certificate .
 */
public class StandardCertificate implements CertificateInterface {

	@Inject
	SignatureSettingInterface settings;

	/** The Constant log. */
	static final Logger log = Logger.getLogger(StandardCertificate.class);

	/** The certificate. */
	protected java.security.cert.X509Certificate certificate;
	
	/** The crl. */
	protected X509CRL crl;
	private byte[] digest;
	private Date endDate;
	private byte[] fingerPrint;
	//private String issuerDN;
	private List<KeyUsage> keyUsage = new ArrayList<KeyUsage>();
	private String label;
	private BigInteger PublicExponent;
	private String serialNumber;
	private Date startDate;
	private String subjectDN;
	private byte[] subjectKeyIdentifier;
	private String userCommonName;
	private byte[] value;
	private X500Name x500name;
	
	/** The issuer. */
	CertificateIssuer issuer;
	
	/**
	 * The Enum KeyUsage.
	 */
	enum KeyUsage{
	           
           	/** The digital signature. */
           	digitalSignature(0),
	           
           	/** The non repudiation. */
           	nonRepudiation(1),
	           //-- recent editions of X.509 have -- renamed this bit to contentCommitment
	           /** The key encipherment. */
           	keyEncipherment(2),
	           
           	/** The data encipherment. */
           	dataEncipherment        (3),
	           
           	/** The key agreement. */
           	keyAgreement            (4),
	           
           	/** The key cert sign. */
           	keyCertSign             (5),
	           
           	/** The c rl sign. */
           	cRLSign                 (6),
	           
           	/** The encipher only. */
           	encipherOnly            (7),
	           
           	/** The decipher only. */
           	decipherOnly            (8);
	           
           	/** The id. */
           	public final int id;
	        private KeyUsage(int i) {
	        	this.id = i;
			}   
	   		
		   	/**
		   	 * Gets the usage.
		   	 *
		   	 * @param _id the _id
		   	 * @return the key usage
		   	 */
		   	public static KeyUsage GetUsage(int _id) {
				KeyUsage[] As = KeyUsage.values();
				for (int i = 0; i < As.length; i++) {
					if (As[i].Compare(_id))
						return As[i];
				}
				return null;
			}
			
			private boolean Compare(int _id) {
				return id == _id;
			}
			
			/**
			 * Gets the id.
			 *
			 * @return the id
			 */
			public  long getID(){
				return id;
			}
			

	}
	
	/**
	 * The Constructor.
	 */
	public StandardCertificate() {
		super();
	}

	/**
	 * Extract cert detail.
	 *
	 * @param certificate the certificate
	 */
	protected void extractCertDetail(X509Certificate certificate) {
			this.certificate = certificate;
			this.startDate = certificate.getNotBefore();
			this.endDate = certificate.getNotAfter();
			this.serialNumber = certificate.getSerialNumber().toString();
	
			MessageDigest md;
			try {
				md = MessageDigest.getInstance("SHA-1");
				this.value = certificate.getEncoded();
				md.update(value);
				this.digest = md.digest();
				this.fingerPrint = Convertors.byte2Hex(digest).getBytes();
			} catch (CertificateEncodingException e1) {
				e1.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
			X500Principal principal = certificate.getSubjectX500Principal();
	
			this.x500name = new X500Name( principal.getName() );
			RDN cn = x500name.getRDNs(BCStyle.CN)[0];
			this.userCommonName = IETFUtils.valueToString(cn.getFirst().getValue());
			this.label = userCommonName + "'s";
			if (certificate.getKeyUsage() != null) {
				// Convert array of boolean to list of understandable values
			
				boolean[] usages = certificate.getKeyUsage();
				for (int i = 0; i<9 ; i++){
				if (usages[i]) {
					keyUsage.add(KeyUsage.GetUsage(i));
				}
			}
			}
			this.subjectKeyIdentifier = certificate.getExtensionValue("2.5.29.14");
			try {
				serialNumber = getExtensionValue(certificate, "1.2.3.4");
			} catch (IOException e) {
				log.error(e);
			}
	
			this.PublicExponent = ((java.security.interfaces.RSAPublicKey) certificate.getPublicKey()).getPublicExponent();
			this.subjectDN = certificate.getSubjectDN().toString();
	
		}

	/**
	 * Extract crl.
	 *
	 * @return the list< certificate revocation list>
	 * @throws CryptoException the gbay crypto exception
	 */
	public List<CertificateRevocationList> extractCRL() throws CryptoException {
		List<CertificateRevocationList> list = new ArrayList<CertificateRevocationList>();
	
		try {
			List<String> crlDistPoints = getCrlDistributionPoints(certificate);
			
			for (String crlDP : crlDistPoints) {
				CertificateRevocationList crl = new CertificateRevocationList(crlDP);
				list.add(crl);
			}
		} catch (CertificateParsingException e) {
			throw new CryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT));
		} catch (CertificateException e) {
			
			throw new CryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT));
		} catch (CRLException e) {
			if (PropertyFileConfiguration.DEBUG){
				e.printStackTrace();
			}
			log.error("CRL Exception happened, CERT's CRL had invalid format");
			throw new CryptoException(new CryptoError(GlobalErrorCode.ENTITY_INCORRECT_FORMAT,"Cert CRL has invalid format"));	
		} catch (IOException e) {
			throw new CryptoException(new CryptoError(GlobalErrorCode.FILE_IO_ERROR));
		} catch (NamingException e) {
			throw new CryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_SIGNATURE));
		}
		return list;
	
	}


	/**
	 * Extracts all CRL distribution point URLs from the
	 * "CRL Distribution Point" extension in a X.509 certificate. If CRL
	 * distribution point extension is unavailable, returns an empty list.
	 */
	private List<String> getCrlDistributionPoints(X509Certificate cert)
			throws CertificateParsingException, IOException {
		 
		byte[] crldpExt = cert
						.getExtensionValue(new ASN1ObjectIdentifier("2.5.29.31").getId());
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
					if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
						GeneralName[] genNames = GeneralNames
								.getInstance(dpn.getName()).getNames();
						// Look for an URI
						for (int j = 0; j < genNames.length; j++) {
							if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
								String url = DERIA5String.getInstance(
										genNames[j].getName()).getString();
								crlUrls.add(url);
							}
						}
					}
				}
				oAsnInStream.close();
				oAsnInStream2.close();
				return crlUrls;
			}

	/**
	 * Gets the crl distrubiution point.
	 *
	 * @return the CRL distrubiution point
	 * @throws IOException the IO exception
	 */
	protected String getCRLDistrubiutionPoint() throws IOException {
		return getExtensionValue("2.5.29.31");
	}

	/**
	 * Gets the digest.
	 *
	 * @return the digest
	 */
	public byte[] getDigest() {
		return digest;
	}

	
	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.keys.CertificateInterface#getEndDate()
	 */
	@Override
	public Date getEndDate() {
		return endDate;
	}

	/**
	 * Gets the extension value.
	 *
	 * @param oid the oid
	 * @return the extension value
	 * @throws IOException the IO exception
	 */
	public String getExtensionValue(String oid) throws IOException {
		return getExtensionValue(certificate, oid);
	}

	private String getExtensionValue(X509Certificate X509Certificate, String oid)
			throws IOException {
				String decoded = null;
				byte[] extensionValue = X509Certificate.getExtensionValue(oid);
			
				if (extensionValue != null) {
					ASN1Primitive derObject = toDERObject(extensionValue);
					if (derObject instanceof DEROctetString) {
						DEROctetString derOctetString = (DEROctetString) derObject;
			
						derObject = toDERObject(derOctetString.getOctets());
						if (derObject instanceof ASN1String) {
							ASN1String s = (ASN1String) derObject;
							decoded = s.getString();
						}
			
					}
				}
				return decoded;
			}

	/**
	 * Gets the finger print.
	 *
	 * @return the finger print
	 */
	public byte[] getFingerPrint() {
		return fingerPrint;
	}

	/**
	 * Gets the issuer dn.
	 *
	 * @return the issuer dn
	 */
	public String getIssuerDN() {
		return certificate.getIssuerDN().toString();
	}

	/**
	 * Gets the label.
	 *
	 * @return the label
	 */
	public String getLabel() {
		return label;
	}

	/**
	 * Gets the public exponent.
	 *
	 * @return the public exponent
	 */
	public BigInteger getPublicExponent() {
		return PublicExponent;
	}

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.keys.CertificateInterface#getSerialNumber()
	 */
	
	/**
	 * Gets the serial number.
	 *
	 * @return the serial number
	 */
	@Override
	public String getSerialNumber() {
		return serialNumber;
	}

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.keys.CertificateInterface#getStartDate()
	 */
	@Override
	public Date getStartDate() {
		return startDate;
	}

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.keys.CertificateInterface#getSubjectDN()
	 */
	@Override
	public String getSubjectDN() {
		return subjectDN;
	}

	/**
	 * Gets the subject key identifier.
	 *
	 * @return the subject key identifier
	 */
	public byte[] getSubjectKeyIdentifier() {
		return subjectKeyIdentifier;
	}

	/**
	 * Gets the user common name.
	 *
	 * @return the user common name
	 */
	public String getUserCommonName() {
		return userCommonName;
	}

	/**
	 * Gets the value.
	 *
	 * @return the value
	 */
	public byte[] getValue() {
		return value;
	}

	/**
	 * Gets the x500name.
	 *
	 * @return the x500name
	 */
	public X500Name getX500name() {
		return x500name;
	}

	/**
	 * Checks if is revoked.
	 *
	 * @param crl the crl
	 * @return true, if checks if is revoked
	 * @throws CryptoException the gbay crypto exception
	 */
	public boolean isRevoked(X509CRL crl) throws CryptoException {
		if (crl==null)
			crl = extractCRL().get(0).getCrl();
		return crl.isRevoked(certificate);
	}

	/**
	 * Sets the value.
	 *
	 * @param value            the value to set
	 */
	public void setValue(byte[] value) {
		this.value = value;
	}

	/**
	 * From http://stackoverflow.com/questions/2409618/how-do-i-decode-a-der-
	 * encoded-string-in-java
	 */
	private ASN1Primitive toDERObject(byte[] data) throws IOException {
		ByteArrayInputStream inStream = new ByteArrayInputStream(data);
		ASN1InputStream asnInputStream = new ASN1InputStream(inStream);
		ASN1Primitive derObject = asnInputStream.readObject();
		asnInputStream.close();
		return derObject;
	}
	
	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.keys.CertificateInterface#getIssuerName()
	 */
	@Override
	public String getIssuerName(){
		return this.issuer.getName();
	}


	/**
	 * Sets the serial number.
	 *
	 * @param SerialNumber the serial number
	 */
	public void setSerialNumber(String SerialNumber) {
		this.serialNumber = SerialNumber;
		
	}



	/**
	 * Sets the subject dn.
	 *
	 * @param sdn the subject dn
	 */
	public void setSubjectDN(String sdn) {
this.subjectDN = sdn;
	}




}