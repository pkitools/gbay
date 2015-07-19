package tools.pki.gbay.crypto.provider;

import java.util.List;

import tools.pki.gbay.crypto.keys.KeyStorage.CoupleKey;

/**
 * To get keys from KeyPairs
 * @author Android
 *
 */
public interface KeySelectionInterface {

	/**
	 * To select a key
	 * @param keyCouples
	 * @return number of the key pair in the list in integer
	 */
	Integer selectKey(List<CoupleKey> keyCouples);

}
