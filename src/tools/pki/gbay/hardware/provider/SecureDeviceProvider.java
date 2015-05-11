package tools.pki.gbay.hardware.provider;

import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;

import tools.pki.gbay.crypto.provider.CryptoServiceProvider;
import tools.pki.gbay.crypto.provider.Type;
import tools.pki.gbay.crypto.texts.EncryptedText;
import tools.pki.gbay.crypto.texts.PlainText;
import tools.pki.gbay.crypto.texts.SignedText;
import tools.pki.gbay.crypto.texts.VerifiedText;
import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.GbayCryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;
import tools.pki.gbay.hardware.pkcs11.TokenFinderInterFace;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SecureDeviceProvider extends PKCS11Supplier implements CryptoServiceProvider{

	Type deviceType;
	TokenFinderInterFace finderListener;
	PKCS11Supplier rt;
	public SecureDeviceProvider(String cryptokiLib, String pin, boolean attach, TokenFinderInterFace multiTokenListener, DeviceFinderInterface multiDeviceListener, RecursiveSignerInterface addAnotherSignatureListener) {
		super(cryptokiLib, pin,multiDeviceListener,addAnotherSignatureListener );
		this.deviceType = Type.smartCard;
		this.finderListener = multiTokenListener;
		  Security.insertProviderAt(new BouncyCastleProvider(), 3);
	}

	public SecureDeviceProvider(String driver, String pin, boolean b) {
		this(driver,pin,b,null,null,null);
	}

	@Override
	public Type getType() {
		return deviceType;
	}

	@Override
	public VerifiedText verify(SignedText text, PlainText originalText)
			throws GbayCryptoException {
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.REQ_METHOD_NOT_ALLOWED));
	}

	

	@Override
	public CMSSignedData getSignedData() throws GbayCryptoException {
		if (variables.signingResult != null)
		return variables.signingResult;
		else{
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.REQ_PARAMETER_FAILED));
		}
	}

	@Override
	public SignedText sign(PlainText text) throws GbayCryptoException {
		variables.plainText = text.toString();
		try{
		signText();
		if (variables.signingResult != null)
			return (new SignedText(variables.plainText, variables.signingResult.getEncoded(), variables.getCerts()));
		} catch (IOException e) {
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.FILE_IO_ERROR));
		} catch (GbayCryptoException e) {
			throw e;
		}
		/*
		finally{
			try {
				PKCS11Manager.dispose();
			} catch (Throwable e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}*/
		return null;
	}

	@Override
	public EncryptedText encrypt(PlainText text) throws GbayCryptoException {
		// TODO Auto-generated method stub
		return null;
	}

}
