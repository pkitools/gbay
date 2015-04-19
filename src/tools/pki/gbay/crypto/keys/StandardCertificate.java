
/*
 * Copyright (c) 2014, Araz
 * All rights reserved.
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

import tools.pki.gbay.configuration.Configuration;
import tools.pki.gbay.crypto.keys.validation.CertificateIssuer;
import tools.pki.gbay.crypto.keys.validation.CertificateRevocationList;
import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.GbayCryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;
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

public class StandardCertificate implements CertificateInterface {
	/** The Constant log. */
	static final Logger log = Logger.getLogger(StandardCertificate.class);

	protected java.security.cert.X509Certificate certificate;
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
	CertificateIssuer issuer;
	enum KeyUsage{
	           digitalSignature(0),
	           nonRepudiation(1),
	           //-- recent editions of X.509 have -- renamed this bit to contentCommitment
	           keyEncipherment(2),
	           dataEncipherment        (3),
	           keyAgreement            (4),
	           keyCertSign             (5),
	           cRLSign                 (6),
	           encipherOnly            (7),
	           decipherOnly            (8);
	           public final int id;
	        private KeyUsage(int i) {
	        	this.id = i;
			}   
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
			public  long getID(){
				return id;
			}
			

	}
	public StandardCertificate() {
		super();
	}

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
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	
			this.PublicExponent = ((java.security.interfaces.RSAPublicKey) certificate.getPublicKey()).getPublicExponent();
			this.subjectDN = certificate.getSubjectDN().toString();
	
		}

	public List<CertificateRevocationList> extractCRL() throws GbayCryptoException {
		List<CertificateRevocationList> list = new ArrayList<CertificateRevocationList>();
	
		try {
			List<String> crlDistPoints = getCrlDistributionPoints(certificate);
			
			for (String crlDP : crlDistPoints) {
				CertificateRevocationList crl = new CertificateRevocationList(crlDP);
				list.add(crl);
			}
		} catch (CertificateParsingException e) {
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT));
		} catch (CertificateException e) {
			
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT));
		} catch (CRLException e) {
			if (Configuration.DEBUG){
				e.printStackTrace();
			}
			log.error("CRL Exception happened, CERT's CRL had invalid format");
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.ENTITY_INCORRECT_FORMAT,"Cert CRL has invalid format"));	
		} catch (IOException e) {
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.FILE_IO_ERROR));
		} catch (NamingException e) {
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_INVALID_SIGNATURE));
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

	protected String getCRLDistrubiutionPoint() throws IOException {
		return getExtensionValue("2.5.29.31");
	}

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

	public byte[] getFingerPrint() {
		return fingerPrint;
	}

	public String getIssuerDN() {
		return certificate.getIssuerDN().toString();
	}

	public String getLabel() {
		return label;
	}

	public BigInteger getPublicExponent() {
		return PublicExponent;
	}

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.keys.CertificateInterface#getSerialNumber()
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

	public byte[] getSubjectKeyIdentifier() {
		return subjectKeyIdentifier;
	}

	public String getUserCommonName() {
		return userCommonName;
	}

	public byte[] getValue() {
		return value;
	}

	public X500Name getX500name() {
		return x500name;
	}

	public boolean isRevoked(X509CRL crl) throws GbayCryptoException {
		if (crl==null)
			crl = extractCRL().get(0).getCrl();
		return crl.isRevoked(certificate);
	}

	/**
	 * @param value
	 *            the value to set
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

	@Override
	public void setEndDate(Date end) {
		this.endDate = end;
		
	}

	@Override
	public void setSerialNumber(String SerialNumber) {
		this.serialNumber = SerialNumber;
		
	}

	@Override
	public void setStartDate(Date start) {
		this.startDate = start;
		
	}

	@Override
	public void setSubjectDN(String sdn) {
this.subjectDN = sdn;
	}

	@Override
	public void setIssuerName(String IssuerName) {
		this.issuer.setName(IssuerName);
	}


}