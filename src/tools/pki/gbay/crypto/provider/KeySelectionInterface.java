package tools.pki.gbay.crypto.provider;

import java.util.List;

import tools.pki.gbay.crypto.keys.KeyStorage.CoupleKey;

public interface KeySelectionInterface {

	Integer selectKey(List<CoupleKey> keyCouples);

}
