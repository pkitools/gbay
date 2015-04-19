package tools.pki.gbay.hardware.pkcs11;

import iaik.pkcs.pkcs11.Token;

public interface TokenFinderInterFace {

	Long selectToken(Token[] tokens);

}
