package tools.pki.gbay.interfaces;

/**
 * To add signers recursively for multiple signers
 * @author Android
 *
 */
public interface RecursiveSignerInterface {

	/**
	 * @param i number of signers till now
	 * @return true if we need to add more
	 */
	boolean addMore(int i);

}
