
package tools.pki.gbay.crypto.texts;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import tools.pki.gbay.configuration.SecurityConcepts;
import tools.pki.gbay.crypto.keys.CertificateInterface;
import tools.pki.gbay.crypto.keys.CertificateValiditor;
import tools.pki.gbay.crypto.keys.validation.CertificateIssuer;
import tools.pki.gbay.crypto.keys.validation.CertificateRevocationList;
import tools.pki.gbay.crypto.provider.CryptoServiceProvider;
import tools.pki.gbay.crypto.provider.SoftCert;
import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.GbayCryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;

/**
 * A signed text which contains signed values and can be verified 
 * @author Araz Farhang
 */
public class SignedText extends PlainText implements SignedTextInterface {
	List<CertificateInterface> signerPublicKey;
	CMSSignedData signedData;

	byte[] signedVal;
	PlainText originalText;
	CertificateIssuer trustedIssuers;
	CertificateRevocationList crl;
	boolean attached;
//	private IssuerPropertyFile issuerPropertyFile;
	

	
	public SignedText(String originaltext , byte[] signedValue, boolean attached) {
		super(signedValue);
		signedVal = signedValue;
		this.originalText = new PlainText(originaltext);
		this.attached = attached;
	}

	public SignedText(String originaltext , byte[] signedValue) {
		super(signedValue);
		signedVal = signedValue;
		this.originalText = new PlainText(originaltext);
		this.attached = false;
	}

	public SignedText(byte[] originaltext , byte[] signedValue) {
		super(signedValue);	
		signedVal = signedValue;
		this.originalText = new PlainText(originaltext);
		this.attached = false;
	}

	public SignedText(String originaltext , CMSSignedData data , boolean attached) throws IOException {
		super(data.getEncoded());
		signedVal = data.getEncoded();
		this.originalText = new PlainText(originaltext);
		this.attached = attached;
	}

    public SignedText(String originaltext , byte[] signedValue , CertificateIssuer trustedIssuer,CertificateRevocationList crl, boolean attached) {
    	super(signedValue);
    	this.signedVal = signedValue;
    	this.originalText = new PlainText(originaltext);
    	this.trustedIssuers = trustedIssuer;
    	this.crl = crl;
    	this.attached = attached;
    }

    @Override
	public EncodedTextInterface toBase64(){
    	return new Base64(this.signedVal);
    }

    
    public SignedText(String originaltext , byte[] signedValue , CertificateIssuer trustedIssuer,CertificateRevocationList crl , List<CertificateInterface> signer) {
    	super(signedValue);
    	this.signedVal = signedValue;
    	this.originalText = new PlainText(originaltext);
    	this.trustedIssuers = trustedIssuer;
    	this.crl = crl;
    	this.signerPublicKey = signer;
    }
    
    
    public SignedText(String originalText , byte[] signedVal, List<CertificateInterface> signerPublicKey) {
		super(signedVal);
		this.signerPublicKey = signerPublicKey;
		this.signedVal = signedVal;
		this.originalText = new PlainText(originalText);
	}
    
    public CMSSignedData detectAttached() throws CMSException{
    	CMSSignedData signedData = new CMSSignedData(signedVal); 
		CMSProcessable processable = signedData.getSignedContent();
		if (processable == null){
			System.out.println("Not attached");
			attached = false;
		}
		else{
			System.out.println("Is attached");
			attached = true;
		}
		return signedData;
    }

    public void ExtractCertificate() throws GbayCryptoException{
    		signerPublicKey = new ArrayList<CertificateInterface>();
    	try {

    	
    		CMSSignedData cms = detectAttached();
    		
    		//

    			Store store = cms.getCertificates();
    			SignerInformationStore signers = cms.getSignerInfos();
    			Collection c = signers.getSigners();
    			Iterator it = c.iterator();
    			while (it.hasNext()) {
    				SignerInformation signer = (SignerInformation) it.next();
    				Collection certCollection = store.getMatches(signer.getSID());
    				Iterator certIt = certCollection.iterator();
    				X509CertificateHolder certHolder = (X509CertificateHolder) certIt .next();
    				X509Certificate currentCert = new JcaX509CertificateConverter().setProvider(
    						SecurityConcepts.getProviderName()).getCertificate(
    						certHolder);
    				CertificateValiditor mykey = new CertificateValiditor(currentCert);
    				signerPublicKey.add(mykey);
    				
    			}
    		} catch (CertificateException e) {
    			e.printStackTrace();
    			throw new GbayCryptoException(
    					new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT));
    		
			} catch (CMSException e) {
				throw new GbayCryptoException(
    					new CryptoError(GlobalErrorCode.SIG_INVALID));
    		
			}
    	
    }
	public SignedText() {
		super();
	}


	

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.texts.SignedTextInterface#getSignedVal()
	 */
	@Override
	public byte[] getSignedVal() {
		return signedVal;
	}

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.texts.SignedTextInterface#setSignedVal(byte[])
	 */
	@Override
	public void setSignedVal(byte[] signedVal) {
		this.byteRep = signedVal;
		this.signedVal = signedVal;
	}

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.texts.SignedTextInterface#getOriginalText()
	 */
	@Override
	public PlainText getOriginalText() {
		return originalText;
	}

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.texts.SignedTextInterface#setOriginalText(tools.pki.gbay.crypto.texts.PlainText)
	 */
	@Override
	public void setOriginalText(PlainText originalText) {
		this.originalText = originalText;
	}
    
	@Override
	public VerificationInterface verify(CryptoServiceProvider csp) throws GbayCryptoException   {
		 return csp.verify(this, getOriginalText());
	 }

	public VerificationInterface verify() throws GbayCryptoException{
		SoftCert sc = new SoftCert();
		return sc.verify(this, this.originalText);
	}
	
	@Override
	public CertificateIssuer getTrustedIssuers() {
		return trustedIssuers;
	}

	@Override
	public void setTrustedIssuers(CertificateIssuer trustedIssuers) {
		this.trustedIssuers = trustedIssuers;
	}

	@Override
	public CertificateRevocationList getCrl() {
		return crl;
	}

	@Override
	public void setCrl(CertificateRevocationList crl) {
		this.crl = crl;
	}


	@Override
	public List<CertificateInterface> getSignerPublicKey() {
		return signerPublicKey;
	}

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.texts.SignedTextInterface#setSignerPublicKey(tools.pki.gbay.crypto.keys.PublicKey)
	 */
	@Override
	public void setSignerPublicKey(List<CertificateInterface> signerPublicKey) {
		this.signerPublicKey = signerPublicKey;
	}

	/**
	 * @return the isEncapsulated
	 */
	public boolean isAttached() {
		return attached;
	}

	/**
	 * @param isEncapsulated the isEncapsulated to set
	 */
	public void setAttached(boolean isEncapsulated) {
		this.attached = isEncapsulated;
	}


 

}
