package tools.pki.gbay.crypto.keys.validation;

/**
 * Interface for certificate validation results
 * @author Android
 *
 */
public interface ValidationResultInterface {

	/**
	 * @return true if it is expired
	 */
	public abstract boolean isExpired();

	/**
	 * @return true of CA is not a valid one
	 */
	public abstract boolean isInvalidCA();

	/**
	 * @return the notStarted
	 */
	public abstract boolean isNotStarted();

	/**
	 * @return the revoked
	 */
	public abstract boolean isRevoked();

	/**
	 * @return true if certificate validation is totally passed and is valid
	 */
	public abstract boolean isPassed();

	/**
	 * @param expired the expired to set
	 */
	public abstract void setExpired(boolean expired);

	/**
	 * @param invalidCA the invalidCA to set
	 */
	public abstract void setInvalidCA(boolean invalidCA);

	/**
	 * @param notStarted the notStarted to set
	 */
	public abstract void setNotStarted(boolean notStarted);

	/**
	 * @param revoked the revoked to set
	 */
	public abstract void setRevoked(boolean revoked);

}