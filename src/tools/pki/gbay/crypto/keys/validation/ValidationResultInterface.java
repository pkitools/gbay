package tools.pki.gbay.crypto.keys.validation;

public interface ValidationResultInterface {

	/**
	 * @return the expired
	 */
	public abstract boolean isExpired();

	/**
	 * @return the invalidCA
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