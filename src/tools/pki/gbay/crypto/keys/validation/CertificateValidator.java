package tools.pki.gbay.crypto.keys.validation;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;



import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.GbayCryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;

public class CertificateValidator {
	enum ValidationMethod {
		CHECK_CRL, CHECK_EXPIRATION_DATE, CHECK_ROOT
	}

	/** The Constant log. */
	static final Logger log = Logger.getLogger(CertificateValidator.class);

//	/** Revocation list's address. */
//	private String[] _CRLaddress = null;

	/** The result. {@link CertificateValidationResult} of the used functions */
	private CertificateValidationResult result = new CertificateValidationResult();

	/** List of {@link CertificateIssuer}s. */
	private Set<CertificateIssuer> _trustedissuers;

	/** X509Certificate�that we want to validate it. */
	private X509Certificate _cert;

	/** Allowed certificate issuers. */
//	private String _trustedrootsdir;

	private X509CRL crl;

	/**
	 * Generate a validator object.
	 * 
	 * @param _cert
	 *            the X509certificate object which we want to validate it
	 * @param _trustedroots
	 *            List of {@link CertificateIssuer}s<br>
	 *            The addresses should be absolute path.
	 *            <p>
	 *            certificate that are issued by these issuers can be trusted.
	 *            </p>
	 */
	public CertificateValidator(X509Certificate _cert,	Set<CertificateIssuer> _trustedroots, X509CRL crl) {
		super();
		this._cert = _cert;
		this._trustedissuers = _trustedroots;
		this.crl = crl;
	}

	public CertificateValidator(X509Certificate _cert,CertificateIssuer _trustedroot, X509CRL crl) throws GbayCryptoException {
		super();
		this._cert = _cert;
		log.debug("Setting cert issuers");
		if (_trustedroot !=null){
			this._trustedissuers = new HashSet<CertificateIssuer>();
			this._trustedissuers.add(_trustedroot);
		}
		else{
			log.error("_trusted roots are null");
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_ISSUER_NOT_SET));			
		}
		log.debug("setting cert CRL");
		if (crl!=null)
			this.crl = crl;
		else{
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_CRL_NOT_SET));
		}
	}

	public boolean isValid() {
		return isValid();
	}

	public CertificateValidationResult validate() throws GbayCryptoException {
		CertificateValidationResult cvr = new CertificateValidationResult();
		if (crl != null)
			cvr.revoked = validateRevocation();
		cvr.expired = isExpired();
		cvr.notStarted = !isStarted();
		if (_trustedissuers != null && _trustedissuers.size()>0){
		try{
			log.info("Number of issuers : "+ _trustedissuers.size());
			cvr.setInvalidCA(validateRoot());
		}
		catch (GbayCryptoException e){
			throw new GbayCryptoException(e);
		}
		}
		return cvr;
	}

	public CertificateValidationResult getResult(
			Set<ValidationMethod> validationtypes) throws GbayCryptoException {
		CertificateValidationResult cvr = new CertificateValidationResult();
		if (validationtypes.contains(ValidationMethod.CHECK_CRL) && crl!=null) {
			cvr.revoked = validateRevocation();
		}
		if (validationtypes.contains(ValidationMethod.CHECK_EXPIRATION_DATE)) {
			cvr.expired = isExpired();
			cvr.notStarted = !isStarted();
		}
		if (validationtypes.contains(ValidationMethod.CHECK_ROOT)) {
			cvr.setInvalidCA(validateRoot());
		}
		return cvr;
	}

	/**
	 * check cert issuer DN if it's coming from a known CA. <br>
	 * It can verify over list of issuer names , list of root cert addresses or
	 * a folder containing root certs regarding to the way that object is
	 * constructed</br>
	 * 
	 * @return true, if successful
	 * @throws CertificateException
	 *             the certificate exception
	 * @throws InvalidAlgorithmParameterException
	 *             the invalid algorithm parameter exception
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 * @throws CertPathValidatorException
	 *             the cert path validator exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public boolean validateRoot() throws GbayCryptoException {

		log.debug("Validating root certs");
		_cert.getPublicKey();
		boolean trusted = true;

		if (_trustedissuers == null || _trustedissuers.size() < 1) {
			log.error("No trusted issuer is in the system. ");
			
			throw new GbayCryptoException(new CryptoError(
					GlobalErrorCode.CERT_ISSUER_NOT_FOUND));
		} else {
			Iterator<CertificateIssuer> iterator = _trustedissuers.iterator();

			while (trusted && iterator.hasNext()) {
				trusted = checkIssuer(iterator.next());
			}
		}
		return trusted;

	}

	/**
	 * Checks if the certificate is a valid one. it verifies the certificate
	 * chain over a root certificate.
	 * 
	 * @param caPath
	 *            the address of certificate authority's cer file
	 * @return True if chain is verified, false if chain can't be verified
	 * @throws GbayCryptoException
	 */
	private boolean checkIssuer(CertificateIssuer issuer) throws GbayCryptoException {
		{
			log.debug("Check the issuer");
			if (issuer != null) {
				try {
					Certificate trust = issuer.getCertificate();

					log.debug("Root Certificate: " + trust);

					/**
					 * Put cert extracted from signature to ByteArrayInputStream
					 * and generate cert from there
					 */

					if (trust != null) {
						CertificateFactory cf = CertificateFactory
								.getInstance("X.509");
				//		ByteArrayInputStream bis = new ByteArrayInputStream(
				//				_cert.getEncoded());
						List<X509Certificate> certList = new ArrayList<X509Certificate>();

						certList.add(issuer.getCertificate());

						CertPath cp = cf.generateCertPath(certList);

						TrustAnchor anchor = new TrustAnchor(
								(X509Certificate) trust, null);

						PKIXParameters params;

						params = new PKIXParameters(
								Collections.singleton(anchor));

						params.setRevocationEnabled(false);
						CertPathValidator cpv;
						//cpv.validate(certPath, params)
						cpv = CertPathValidator.getInstance("PKIX");

						PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) cpv
								.validate(cp, params);
						log.debug(result.toString());
						return true;
					}

					else if (issuer.getName() != null){
						log.debug("Issuer did not contain root cert but just the name:"+ issuer.getName() + tools.pki.gbay.configuration.Configuration.StarLine + "Cert issuer:"+_cert.getIssuerDN().getName().toString());
						return _cert.getIssuerDN().getName().toString()
								.contains(issuer.getName());
					}
				} catch (InvalidAlgorithmParameterException e) {
					log.error(e.getMessage());
					// result.set_pathisinvalid(true);
					return false;
				} catch (CertificateException e) {
					log.error(e.getMessage());
					return false;

				} catch (NoSuchAlgorithmException e) {
					log.error(e.getMessage());
					return false;
				} catch (CertPathValidatorException e) {
					log.error(e.getMessage());
					return false;
				}

			} else {
				log.error("You haven't send any issuer to validate..");
				throw new GbayCryptoException(new CryptoError(
						GlobalErrorCode.CERT_ISSUER_NOT_SET));
			}
		}
		return false;
	}

	public boolean validatePeriod() {
		return isExpired() && isStarted();
	}

	/**
	 * Checks if the certificate is expired.
	 * 
	 * @return true if certificate is expired
	 */
	public boolean isExpired() {
		boolean expired = false;
		Date notAfter = _cert.getNotAfter();
		long currentTime = System.currentTimeMillis();
		long expiryTime = notAfter.getTime();
		log.debug(expiryTime + " Current time: " + currentTime);
		expired = (expiryTime < currentTime);
		result.expired = expired;
		return expired;
	}

	/**
	 * Checks if certificate validation period is started.
	 * 
	 * @return true, if is started
	 */
	public boolean isStarted() {
		boolean started = false;
		Date notBefore = _cert.getNotBefore();
		long currentTime = System.currentTimeMillis();
		long startTime = notBefore.getTime();
		log.debug(startTime + " Current time: " + currentTime);
		started = (startTime <= currentTime);
		result.notStarted = !started;
		log.info("Certificate is started : "+started);
		return started;
	}

	public boolean validateRevocation() throws GbayCryptoException {
		if (crl == null) {
			log.debug("crl in certificate validatore is null");
			throw new GbayCryptoException(new CryptoError(GlobalErrorCode.CERT_CRL_NOT_FOUND));
		}
		return crl.isRevoked(_cert);
	}

}
