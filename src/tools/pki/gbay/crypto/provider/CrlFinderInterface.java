package tools.pki.gbay.crypto.provider;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

public interface CrlFinderInterface {

	X509CRL getCrl(X509Certificate cert);

}
