package tools.pki.gbay.crypto.keys.validation;

/**
 * Result of a certificate validation
 * @author Android
 *
 */
public class CertificateValidationResult implements ValidationResultInterface {
boolean expired;
protected boolean invalidCA;
boolean notStarted;
boolean revoked;
/* (non-Javadoc)
 * @see tools.pki.gbay.crypto.keys.validation.ValidationResultInterface#isExpired()
 */
@Override
public boolean isExpired() {
	return expired;
}
/* (non-Javadoc)
 * @see tools.pki.gbay.crypto.keys.validation.ValidationResultInterface#isInvalidCA()
 */
@Override
public boolean isInvalidCA() {
	return invalidCA;
}
/* (non-Javadoc)
 * @see tools.pki.gbay.crypto.keys.validation.ValidationResultInterface#isNotStarted()
 */
@Override
public boolean isNotStarted() {
	return notStarted;
}
/* (non-Javadoc)
 * @see tools.pki.gbay.crypto.keys.validation.ValidationResultInterface#isRevoked()
 */
@Override
public boolean isRevoked() {
	return revoked;
}
/* (non-Javadoc)
 * @see tools.pki.gbay.crypto.keys.validation.ValidationResultInterface#isPassed()
 */
@Override
public boolean isPassed(){
	return (!revoked && !expired && !notStarted && !invalidCA);
}
/* (non-Javadoc)
 * @see tools.pki.gbay.crypto.keys.validation.ValidationResultInterface#setExpired(boolean)
 */
@Override
public void setExpired(boolean expired) {
	this.expired = expired;
}
/* (non-Javadoc)
 * @see tools.pki.gbay.crypto.keys.validation.ValidationResultInterface#setInvalidCA(boolean)
 */
@Override
public void setInvalidCA(boolean invalidCA) {
	this.invalidCA = invalidCA;
}
/* (non-Javadoc)
 * @see tools.pki.gbay.crypto.keys.validation.ValidationResultInterface#setNotStarted(boolean)
 */
@Override
public void setNotStarted(boolean notStarted) {
	this.notStarted = notStarted;
}

/* (non-Javadoc)
 * @see tools.pki.gbay.crypto.keys.validation.ValidationResultInterface#setRevoked(boolean)
 */
@Override
public void setRevoked(boolean revoked) {
	this.revoked = revoked;
}

}
