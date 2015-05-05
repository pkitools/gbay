package tools.pki.gbay.errors;

public class GbayCryptoException extends Throwable{

	public GbayCryptoException(CryptoError cryptoError) {
		// TODO Auto-generated constructor stub
	}
	public GbayCryptoException(GlobalErrorCode txnFail,String message) {
		// TODO Auto-generated constructor stub
	}
	public GbayCryptoException(Exception e) {
		// TODO Auto-generated constructor stub
	}

	public GbayCryptoException(String string) {
		// TODO Auto-generated constructor stub
	}

	public GbayCryptoException(CryptoError cryptoError, Exception e) {
		// TODO Auto-generated constructor stub
	}

	public GbayCryptoException(GbayCryptoException e) {
		// TODO Auto-generated constructor stub
	}

	public GbayCryptoException(GlobalErrorCode fileIoError) {
		// TODO Auto-generated constructor stub
	}

	public Object getErrorCode() {
		// TODO Auto-generated method stub
		return null;
	}


}
