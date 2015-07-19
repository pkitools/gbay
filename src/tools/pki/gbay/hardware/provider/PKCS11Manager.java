package tools.pki.gbay.hardware.provider;

import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs11.wrapper.CK_INFO;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM_INFO;
import iaik.pkcs.pkcs11.wrapper.CK_SLOT_INFO;
import iaik.pkcs.pkcs11.wrapper.CK_TOKEN_INFO;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11;
import iaik.pkcs.pkcs11.wrapper.PKCS11Connector;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.PrivilegedActionException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

import org.apache.log4j.Logger;

import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.CryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;

/**
 * This class uses the PKCS#11 Java api provieded by <a
 * href="http://jce.iaik.tugraz.at/products/14_PKCS11_Wrapper/index.php">IAIK
 * pkcs11 wrapper </a> to perform PKCS#11 digital signature operations. <br>
 * <br>
 * Here we use only a low-level subset of the wrapper's api (distributed in the
 * GBay Hardware Devices installer package), so to minimize the weight of the relative jar
 * files in a signing environment.
 * <p>
 * Several methods are designed to ease object retrieval during 
 * digital signature process. See
 * {@link PKCS11Manager#findCertificateWithNonRepudiationCritical()}for details.
 * We have some token managment functions and need to add more and more... 
 * Hopefully I can finish this :D
 * @author Araz Farhang
 */
public class PKCS11Manager {

	 public static final int CKR_OBJECT_HANDLE_INVALID = 0x00000082;
     public static final int CKR_OPERATION_ACTIVE = 0x00000090;
     public static final int CKR_OPERATION_NOT_INITIALIZED = 0x00000091;
     public static final int CKR_PIN_INCORRECT = 0x000000A0;
     public static final int CKR_PIN_INVALID = 0x000000A1;
     public static final int CKR_PIN_LEN_RANGE = 0x000000A2;

     /* CKR_PIN_EXPIRED and CKR_PIN_LOCKED are new for v2.0 */
     public static final int CKR_PIN_EXPIRED = 0x000000A3;
     public static final int CKR_PIN_LOCKED = 0x000000A4;
     public static final int CKR_SESSION_CLOSED = 0x000000B0;
     public static final int CKR_SESSION_COUNT = 0x000000B1;
     public static final int CKR_SESSION_HANDLE_INVALID = 0x000000B3;
     public static final int CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0x000000B4;
     public static final int CKR_SESSION_READ_ONLY = 0x000000B5;
     public static final int CKR_SESSION_EXISTS = 0x000000B6;
    /**
     * The <code>cryptokiLibrary</code> is the native library implementing the
     * <code>PKCS#11</code> specification.
     */
    private java.lang.String cryptokiLibrary = null;

    /**
     * The PKCS#11 session identifier returned when a session is opened. Value
     * is -1 if no session is open.
     */
    private long sessionHandle = -1L;

    /**
     * The PKCS#11 token identifier. Value is -1 if there is no current token.
     */
    private long tokenHandle = -1L;;

    /**
     * The java object wrapping criptoki library functionalities.
     */
    private PKCS11 pkcs11Module = null;

    /**
     * PKCS#11 identifier for the signature algorithm.
     */
    private CK_MECHANISM signatureMechanism = null;

    /**
     * The <code>Log4j</code> where logging messages are written.
     *  
     */
    private Logger log = Logger.getLogger(PKCS11Manager.class);

   
    /**
     * An instance of this class inorder to have a <code>singletone</code>
     */
    private static PKCS11Manager instance = null;
    
    /**
     * Indicates if cryptokey is initialised
     */
	private boolean isInitialized;
	
   
	/**
	 * The information of connected slot
	 */
	private HashMap<Long, CK_SLOT_INFO>  slotInfo = new HashMap<Long, CK_SLOT_INFO>();

	/**
	 * Information of connected token
	 */
	private HashMap<Long, CK_TOKEN_INFO>  tokenInfo = new HashMap<Long, CK_TOKEN_INFO>();
    
    /**
     * The module that is in use
     */
    private CK_INFO moduleInfo;
    
    /**
     * A token with the current cryptokey is connected
     */
//    private boolean tokenConnected = false;
    
	/**
	 * Get the PKCS11 device manager
	 * @param cryptokiLib PKCS11 driver library address
	 * @return
	 * @throws CryptoException PKCS11 Exceptions
	 * @throws IOException
	 * @throws TokenException
	 */
    public static PKCS11Manager getInstance(String cryptokiLib) throws CryptoException, IOException, TokenException {

    	if(instance == null) {
	         return new PKCS11Manager(cryptokiLib);
	      }
	      else{
	    		  try {
	    				dispose2();
	    			
				} catch (Throwable e) {
					
					e.printStackTrace();
				}
	    		
	    		  instance = new PKCS11Manager(cryptokiLib);
	      }
	      return instance;
	  }



	private static void dispose2() throws Throwable {
		if (instance !=null){
			instance.closeSession();
			instance.libFinalize();
			instance = null;
		}
		
		
	}
	
    @SuppressWarnings("unused")
	private PKCS11Manager(String cryptokiLib, long mechanism,
            java.io.PrintStream out) throws IOException, TokenException, CryptoException, PrivilegedActionException {

        this(cryptokiLib);
        initializeTokenAndMechanism(mechanism);
    }

    
    /*
    protected PKCS11Manager(String cryptokiLib)
            throws CryptoException, PrivilegedActionException, PKCS11Exception {
        super();
try{
	/*
	prevLIB = cryptokiLibrary;
	          cryptokiLibrary = cryptokiLib;
	
	          log.debug("\n\nInitializing PKCS11Manager...\n");
        log.debug("Trying to connect to PKCS#11 module: '" + cryptokiLibrary
                + "' ...");
        
		if (prevLIB!=cryptokiLibrary && prevLIB !=null && cryptokiLib !=null){
			System.err.println("Old lib was there");
			try {
				
				pkcs11Module.finalize();
			} catch (Throwable e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			pkcs11Module = null;
			isInitialized = false;

		}*/
/*	Module mymodule = (Module) AccessController
			.doPrivileged(new PrivilegedExceptionAction() {
				public java.lang.Object run() throws IOException {
					Module m = Module.getInstance(cryptokiLibrary);
					return m;
				}
			});


	try {
		
		if (!isInitialized) {
			System.err.println("NOTINIT");
			DefaultInitializeArgs init = new DefaultInitializeArgs();
			mymodule.initialize(init); // initializes the module
			isInitialized = true;
			pkcs11Module = mymodule.getPKCS11Module();
			log.info("Initialised " + pkcs11Module);
		}
	} catch (iaik.pkcs.pkcs11.wrapper.PKCS11Exception ex) {
		System.err.println("ALREADY");

		if (ex.getErrorCode() == PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			log.info("PKCS11 already loaded");
			isInitialized = true;
		} else {

			log.error("Pkcs11 error: " + ex.getMessage());
			isInitialized = false;
			throw new CryptoException(ex);
		}
	}} catch (TokenException e) {
		log.error("Token Exception :" + e.getMessage());
	}
	
	
        
       // pkcs11Module = PKCS11Connector.connectToPKCS11Module(cryptokiLibrary);
       // log.debug("connected.\n");

        initializeLibrary();
       
    }

*/

    

    /**
     * Initialize library 
     * @param cryptokiLib library file address
     * @throws IOException
     * @throws TokenException
     * @throws CryptoException
     */
    public PKCS11Manager(String cryptokiLib)
            throws IOException, TokenException, CryptoException {
        super();

        cryptokiLibrary = cryptokiLib;

        log.info("\n\nInitializing PKCS11Manager...\n");

        log.info("Trying to connect to PKCS#11 module: '" + cryptokiLibrary
                + "' ...");
        pkcs11Module = PKCS11Connector.connectToPKCS11Module(cryptokiLibrary);
        log.info("connected.\n");

        initializeLibrary();
    }

    /**
     * Initializes cryptoki library operations.
     * 
     * @throws PKCS11Exception
     * @throws CryptoException 
     */
    private void initializeLibrary() throws  CryptoException {
        log.info("\ninitializing module ... ");
        try{
        	pkcs11Module.C_Initialize(null,false);
        	log.info("initialized.\n");
   
        } 
        catch (iaik.pkcs.pkcs11.wrapper.PKCS11Exception ex) {
        	System.err.println("ALREADY");
        	if (ex.getErrorCode() == PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        		log.info("PKCS11 already loaded");
        		isInitialized = true;
		} else {
			log.error("Pkcs11 error: " + ex.getMessage());
			isInitialized = false;
			throw new CryptoException(ex);
		}
        }
    
    }

    private void initializeTokenAndMechanism(long mechanism)
            throws PKCS11Exception, CryptoException {
        tokenHandle = getTokenSupportingMechanism(mechanism);

        if (tokenHandle >= 0) {
            log.info("\nSetting signing token handle: " + tokenHandle);
            log.info("\nSetting signing  mechanism id: " + mechanism
                    + " -> " + Functions.mechanismCodeToString(mechanism));

            setMechanism(mechanism);
        }
    }

    private void setMechanism(long mechanism, Object pParameter) {
        this.signatureMechanism = new CK_MECHANISM();
        this.signatureMechanism.mechanism = mechanism;
        this.signatureMechanism.pParameter = pParameter;

    }

    protected void setMechanism(long mechanism) {
        this.setMechanism(mechanism, null);

    }

    /**
     * Closes the default PKCS#11 session.
     * 
     * @throws PKCS11Exception
     */
    public void closeSession() throws PKCS11Exception {
        if (getSession() == -1L)
            return;
        log.info("\nClosing session ...");
        pkcs11Module.C_CloseSession(getSession());
        setSession(-1L);
    }

    /**
     * Closes a specific PKCS#11 session.
     * 
     * @param sessionHandle
     *            handle of the session to close.
     * @throws PKCS11Exception
     */
    public void closeSession(long sessionHandle) throws PKCS11Exception {
        log.info("\nClosing session with handle: " + sessionHandle + " ...");
        pkcs11Module.C_CloseSession(sessionHandle);
    }

    /**
     * Error decoding function. Currently not implemented (returns 'Unknown
     * error' everytime).
     * 
     * 
     * @param GlobalErrorCode
     *            id of the error.
     * @return the decription corresponding to error code.
     */
    public static String decodeError(int GlobalErrorCode) {
        String errorString = "Unknown error.";
        /*
         * switch (GlobalErrorCode) { case PKCS11Exception. : errorString = "PIN
         * errato."; break; case PKCS11Exception.PIN_INVALID : errorString =
         * "PIN non valido."; break; case PKCS11Exception.TOKEN_NOT_PRESENT :
         * errorString = "Inserire la carta."; break; }
         */
        return errorString;
    }

    /**
     * Returns the private key handle, on current token, corresponding to the
     * given textual label.
     * 
     * @param label
     *            the string label to search.
     * @return the integer identifier of the private key, or -1 if no key was
     *         found.
     * @throws PKCS11Exception
     */
    public long findSignatureKeyFromLabel(String label) throws PKCS11Exception {

        long signatureKeyHandle = -1L;

        if (getSession() < 0)
            return -1L;

        log.info("finding signature key with label: '" + label + "'");
        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[2];
        //CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];

        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        attributeTemplateList[0].pValue = new Long(
                PKCS11Constants.CKO_PRIVATE_KEY);

        attributeTemplateList[1] = new CK_ATTRIBUTE();

        attributeTemplateList[1].type = PKCS11Constants.CKA_LABEL;
        attributeTemplateList[1].pValue = label.toCharArray();

        pkcs11Module.C_FindObjectsInit(getSession(), attributeTemplateList,false);
        long[] availableSignatureKeys = pkcs11Module.C_FindObjects(
                getSession(), 100);
        //maximum of 100 at once

        if (availableSignatureKeys == null) {
            log.info("null returned - no signature key found");
        } else {
            log.info("found " + availableSignatureKeys.length
                    + " signature keys, picking first.");
            for (int i = 0; i < availableSignatureKeys.length; i++) {
                if (i == 0) { // the first we find, we take as our signature key
                    signatureKeyHandle = availableSignatureKeys[i];
                    log.debug("for signing we use signature key with handle: "
                                    + signatureKeyHandle);
                }

            }
        }
        pkcs11Module.C_FindObjectsFinal(getSession());

        return signatureKeyHandle;
    }

    /**
     * Returns the private key handle, on current token, corresponding to the
     * given byte[]. ID is often the byte[] version of the label.
     * 
     * @param id
     *            the byte[] id to search.
     * @return the integer identifier of the private key, or -1 if no key was
     *         found.
     * @throws PKCS11Exception
     * @see PKCS11Manager#findSignatureKeyFromLabel(String)
     */
    public long findSignatureKeyFromID(byte[] id) throws PKCS11Exception {

        long signatureKeyHandle = -1L;

        if (getSession() < 0)
            return -1L;

        log.info("finding signature key from id.");
        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[2];

        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        attributeTemplateList[0].pValue = new Long(
                PKCS11Constants.CKO_PRIVATE_KEY);

        attributeTemplateList[1] = new CK_ATTRIBUTE();

        attributeTemplateList[1].type = PKCS11Constants.CKA_ID;
        attributeTemplateList[1].pValue = id;

        pkcs11Module.C_FindObjectsInit(getSession(), attributeTemplateList,false);
        long[] availableSignatureKeys = pkcs11Module.C_FindObjects(
                getSession(), 100);
        //maximum of 100 at once
        if (availableSignatureKeys == null) {
            log.debug("null returned - no signature key found with matching ID");
        } else {
            log.info("found " + availableSignatureKeys.length
                    + " signature keys, picking first.");
            for (int i = 0; i < availableSignatureKeys.length; i++) {
                if (i == 0) { // the first we find, we take as our signature key
                    signatureKeyHandle = availableSignatureKeys[i];
                    log.info("returning signature key with handle: "
                            + signatureKeyHandle);
                }

            }
        }
        pkcs11Module.C_FindObjectsFinal(getSession());

        return signatureKeyHandle;
    }

    /**
     * Returns the first private key handle found on current token.
     * 
     * @return a private key handle, or -1 if no key is found.
     * @throws PKCS11Exception
     */
    public long findSignatureKey() throws PKCS11Exception {

        long signatureKeyHandle = -1L;

        if (getSession() < 0)
            return -1L;

        log.info("finding a signature key...");

        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];

        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        attributeTemplateList[0].pValue = new Long(
                PKCS11Constants.CKO_PRIVATE_KEY);

        pkcs11Module.C_FindObjectsInit(getSession(), attributeTemplateList,false);
        long[] availableSignatureKeys = pkcs11Module.C_FindObjects(
                getSession(), 100);
        //maximum of 100 at once

        if (availableSignatureKeys == null) {
            log.info("null returned - no signature key found");
        } else {
            log.info("found " + availableSignatureKeys.length
                    + " signature keys, picking first.");
            for (int i = 0; i < availableSignatureKeys.length; i++) {
                if (i == 0) { // the first we find, we take as our signature key
                    signatureKeyHandle = availableSignatureKeys[i];
                    log
                            .debug("for signing we use signature key with handle: "
                                    + signatureKeyHandle);
                }

            }
        }
        pkcs11Module.C_FindObjectsFinal(getSession());

        return signatureKeyHandle;
    }

    /**
     * Sign (here means encrypting with private key) the provided data with a
     * single operation. This is the only modality supported by the (currently
     * fixed) RSA_PKCS mechanism.
     * 
     * @param signatureKeyHandle
     *            handle of the private key to use for signing.
     * @param data
     *            the data to sign.
     * @return a byte[] containing signed data.
     * @throws CryptoException 
     * @throws IOException
     * @throws PKCS11Exception
     */
    public byte[] signDataSinglePart(long signatureKeyHandle, byte[] data) throws CryptoException
            {

        byte[] signature = null;
        if (getSession() < 0)
            return null;

        System.out.println("\nStart single part sign operation...");
        try {
			pkcs11Module.C_SignInit(getSession(), this.signatureMechanism,
			        signatureKeyHandle,false);
		
        if ((data.length > 0) && (data.length < 1024)) {
            System.out.println("Signing ...");
            signature = pkcs11Module.C_Sign(getSession(), data);
            System.out.println("FINISHED.");
        } else
            System.out.println("Error in data length!");

        } catch (PKCS11Exception e) {
			
			e.printStackTrace();
			throw new CryptoException(new CryptoError(GlobalErrorCode.PIN_INCORRECT));
		}
        return signature;

    }

    /**
     * Sign (here means digesting and encrypting with private key) the provided
     * data with a multiple-pass operation. This is the a modality supported by
     * CKM_SHA1_RSA_PKCS, for example, that digests and ecrypts data. Note that
     * some Infocamere card-cryptoki combinations does not supports this type of
     * mechanisms.
     * 
     * @param signatureKeyHandle
     *            handle of the private key to use for signing.
     * @param dataStream
     *            an <code>InputStram</code> providing data to sign.
     * @return a byte[] containing signed data.
     * @throws IOException
     * @throws PKCS11Exception
     */
    public byte[] signDataMultiplePart(long signatureKeyHandle,
            InputStream dataStream) throws IOException, PKCS11Exception {

        byte[] signature = null;
        byte[] buffer = new byte[1024];
        byte[] helpBuffer;
        int bytesRead;

        System.out.println("\nStart multiple part sign operation...");
        pkcs11Module.C_SignInit(getSession(), this.signatureMechanism,
                signatureKeyHandle,false);

        while ((bytesRead = dataStream.read(buffer, 0, buffer.length)) >= 0) {
            helpBuffer = new byte[bytesRead];
            // we need a buffer that only holds what to send for signing
            System.arraycopy(buffer, 0, helpBuffer, 0, bytesRead);
            System.out.println("Byte letti: " + bytesRead);

            pkcs11Module.C_SignUpdate(getSession(), helpBuffer);

            Arrays.fill(helpBuffer, (byte) 0);
        }

        Arrays.fill(buffer, (byte) 0);
        signature = pkcs11Module.C_SignFinal(getSession());

        return signature;
    }

    /**
     * look for a RSA key and encrypt ...
     * @param label label of the device to look for
     * @param digest digest to be encrypted
     * @return encrypted value
     * @throws PKCS11Exception
     * @throws CryptoException
     */
    protected byte[] encryptDigest(String label, byte[] digest)
            throws PKCS11Exception, CryptoException {

        byte[] encryptedDigest = null;

        long sessionHandle = getSession();
        if (sessionHandle < 0)
            return null;

        long signatureKeyHandle = findSignatureKeyFromLabel(label);

        if (signatureKeyHandle > 0) {
            log.info("\nStarting digest encryption...");
            encryptedDigest = signDataSinglePart(signatureKeyHandle, digest);
        } else {
            //         we have not found a suitable key, we cannot contiue
        }

        return encryptedDigest;
    }

    /**
     * Queries the a specific token for a certificate suitable for a legal value
     * subscription. See
     * {@link PKCS11Manager#findCertificateWithNonRepudiationCritical()}.
     * 
     * @see findCertificateWithNonRepudiationCritical()
     * 
     * @param token
     *            ID of the token to query for the certificate.
     * @return the handle of the required certificate, if found; -1 otherwise.
     * @throws TokenException
     * @throws CertificateException
     */

    public long findCertificateWithNonRepudiationCritical(long token)
            throws TokenException, CertificateException {

        long certKeyHandle = -1L;

        long s = openSession(token);

        if (s == -1L) {
            log.info("Unable to open a session on token with handle: "
                    + token);
            return -1L;
        }

        log.info("finding a certificate with "
                + "Critical KeyUsage including non repudiation\n"
                + " on token with handle: " + token);

        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];

        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        attributeTemplateList[0].pValue = new Long(
                PKCS11Constants.CKO_CERTIFICATE);

        pkcs11Module.C_FindObjectsInit(s, attributeTemplateList,false);
        long[] availableCertificates = pkcs11Module.C_FindObjects(s, 100);
        //maximum of 100 at once
        pkcs11Module.C_FindObjectsFinal(s);

        if (availableCertificates == null) {
            log.info("null returned - no certificate key found");
        } else {
            log.info("found " + availableCertificates.length
                    + " certificates");

            byte[] certBytes = null;
            java.security.cert.X509Certificate javaCert = null;
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
                    .getInstance("X.509");
            java.io.ByteArrayInputStream bais = null;
            for (int i = 0; (i < availableCertificates.length)
                    && (certKeyHandle < 0); i++) {
                log.info("Checking KeyUsage for certificate with handle: "
                        + availableCertificates[i]);
                certBytes = getDEREncodedCertificate(availableCertificates[i], s);
                bais = new java.io.ByteArrayInputStream(certBytes);
                javaCert = (java.security.cert.X509Certificate) cf
                        .generateCertificate(bais);
                if (isKeyUsageNonRepudiationCritical(javaCert)) {
                    certKeyHandle = availableCertificates[i];
                    log.info("Check OK!");
                } else
                    log.info("Check failed.");
            }
        }

        closeSession(s);

        return certKeyHandle;
    }

    /**
     * Queries the current token for a certificate suitable for a legal value
     * subscription.
     * <p>
     * According to the italian law, if you want give to the digital signature
     * the maximum legal value (equivalent to a signature on paper), and also
     * for the sake of interoperability, the signer certificate has to satisfy
     * some costraints. See <a
     * href="http://www.cnipa.gov.it/site/_contentfiles/00127900/127910_CR%2024_2000.pdf">
     * the official document in PDF format <a>or <a
     * href="http://www.interlex.it/testi/interop.htm"> this html page <a>(only
     * in italian, sorry) for details.
     * <p>
     * In particular, the certificate has to carry a KeyUsage extension of 'non
     * repudiation' (OID: 2.5.29.15) marked as critical.
     * 
     * 
     * @return the handle of the required certificate, if found; -1 otherwise.
     * @throws TokenException
     * @throws CertificateException
     */
    public long findCertificateWithNonRepudiationCritical()
            throws TokenException, CertificateException {

        long certKeyHandle = -1L;

        if (getSession() < 0)
            return -1L;

        log
                .debug("finding a certificate with Critical KeyUsage including non repudiation ...");

        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];

        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        attributeTemplateList[0].pValue = new Long(
                PKCS11Constants.CKO_CERTIFICATE);

        pkcs11Module.C_FindObjectsInit(getSession(), attributeTemplateList, false);
        long[] availableCertificates = pkcs11Module.C_FindObjects(getSession(),
                100);
        //maximum of 100 at once
        pkcs11Module.C_FindObjectsFinal(getSession());

        if (availableCertificates == null) {
            log.info("null returned - no certificate key found");
        } else {
            log.info("found " + availableCertificates.length
                    + " certificates");

            byte[] certBytes = null;
            java.security.cert.X509Certificate javaCert = null;
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
                    .getInstance("X.509");
            java.io.ByteArrayInputStream bais = null;
            for (int i = 0; (i < availableCertificates.length)
                    && (certKeyHandle < 0); i++) {
                log.info("Checking KeyUsage for certificate with handle: "
                        + availableCertificates[i]);
                certBytes = getDEREncodedCertificate(availableCertificates[i]);
                bais = new java.io.ByteArrayInputStream(certBytes);
                javaCert = (java.security.cert.X509Certificate) cf
                        .generateCertificate(bais);
                if (isKeyUsageNonRepudiationCritical(javaCert)) {
                    certKeyHandle = availableCertificates[i];
                    log.info("Check OK!");
                } else
                    log.info("Check failed.");
            }
        }

        return certKeyHandle;
    }

    /**
     * checks Key Usage constraints of a java certificate.
     * 
     * @param javaCert
     *            the certificate to check as java object.
     * @return true if the given certificate has a KeyUsage extension of 'non
     *         repudiation' (OID: 2.5.29.15) marked as critical.
     * @see PKCS11Manager#findCertificateWithNonRepudiationCritical()
     */
    boolean isKeyUsageNonRepudiationCritical(
            java.security.cert.X509Certificate javaCert) {

        boolean isNonRepudiationPresent = false;
        boolean isKeyUsageCritical = false;

        Set<String> oids = javaCert.getCriticalExtensionOIDs();
        if (oids != null)
            // check presence between critical extensions of oid:2.5.29.15
            // (KeyUsage)
            isKeyUsageCritical = oids.contains("2.5.29.15");

        boolean[] keyUsages = javaCert.getKeyUsage();
        if (keyUsages != null)
            //check non repudiation (index 1)
            isNonRepudiationPresent = keyUsages[1];

        return (isKeyUsageCritical && isNonRepudiationPresent);

    }

    /**
     * Finds a certificate matching the given byte[] id.
     * 
     * @param id
     * @return the handle of the certificate, or -1 if not found.
     * @throws PKCS11Exception
     */
    public long findCertificateFromID(byte[] id) throws PKCS11Exception {

        long sessionHandle = getSession();
        long certificateHandle = -1L;

        if (sessionHandle < 0 || id == null)
            return -1L;

        log.info("find certificate from id.");

        // now get the certificate with the same ID as the signature key
        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[2];

        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        attributeTemplateList[0].pValue = new Long(
                PKCS11Constants.CKO_CERTIFICATE);
        attributeTemplateList[1] = new CK_ATTRIBUTE();
        attributeTemplateList[1].type = PKCS11Constants.CKA_ID;
        attributeTemplateList[1].pValue = id;

        pkcs11Module.C_FindObjectsInit(getSession(), attributeTemplateList,false);
        long[] availableCertificates = pkcs11Module.C_FindObjects(getSession(),
                100);
        //maximum of 100 at once
        if (availableCertificates == null) {
            log.info("null returned - no certificate found");
        } else {
            log.info("found " + availableCertificates.length
                    + " certificates with matching ID");
            for (int i = 0; i < availableCertificates.length; i++) {
                if (i == 0) { // the first we find, we take as our certificate
                    certificateHandle = availableCertificates[i];
                    System.out.print("for verification we use ");
                }
                log.info("certificate " + i);
            }
        }
        pkcs11Module.C_FindObjectsFinal(getSession());

        return certificateHandle;
    }

    /**
     * Finds a certificate matching the given textual label.
     * 
     * @param label
     * @return the handle of the certificate, or -1 if not found.
     * @throws PKCS11Exception
     */
    public long findCertificateFromLabel(char[] label) throws PKCS11Exception {

        long sessionHandle = getSession();
        long certificateHandle = -1L;

        if (sessionHandle < 0 || label == null)
            return -1L;

        log.info("find certificate from label.");

        // now get the certificate with the same ID as the signature key
        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[2];

        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        attributeTemplateList[0].pValue = new Long(
                PKCS11Constants.CKO_CERTIFICATE);
        attributeTemplateList[1] = new CK_ATTRIBUTE();
        attributeTemplateList[1].type = PKCS11Constants.CKA_LABEL;
        attributeTemplateList[1].pValue = label;

        pkcs11Module.C_FindObjectsInit(getSession(), attributeTemplateList , false);
        long[] availableCertificates = pkcs11Module.C_FindObjects(getSession(),
                100);
        //maximum of 100 at once
        if (availableCertificates == null) {
            log.info("null returned - no certificate found");
        } else {
            log.info("found " + availableCertificates.length
                    + " certificates with matching ID");
            for (int i = 0; i < availableCertificates.length; i++) {
                if (i == 0) { // the first we find, we take as our certificate
                    certificateHandle = availableCertificates[i];
                    System.out.print("for verification we use ");
                }
                log.info("certificate " + i);
            }
        }
        pkcs11Module.C_FindObjectsFinal(getSession());

        return certificateHandle;
    }

    /**
     * Searches the certificate corresponding to the private key identified by
     * the given handle; this method assumes that corresponding certificates and
     * private keys are sharing the same byte[] IDs.
     * 
     * @param signatureKeyHandle
     *            the handle of a private key.
     * @return the handle of the certificate corrisponding to the given key.
     * @throws PKCS11Exception
     */
    public long findCertificateFromSignatureKeyHandle(long signatureKeyHandle)
            throws PKCS11Exception {

        long sessionHandle = getSession();

        if (sessionHandle < 0)
            return -1L;

        log.info("\nFind certificate from signature key handle: "
                + signatureKeyHandle);

        // first get the ID of the signature key
        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];
        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_ID;

        pkcs11Module.C_GetAttributeValue(getSession(), signatureKeyHandle,
                attributeTemplateList , false);

        byte[] keyAndCertificateID = (byte[]) attributeTemplateList[0].pValue;
        log.info("ID of signature key: "
                + Functions.toHexString(keyAndCertificateID));

        return findCertificateFromID(keyAndCertificateID);
    }

    /**
     * Searches the private key corresponding to the certificate identified by
     * the given handle; this method assumes that corresponding certificates and
     * private keys are sharing the same byte[] IDs.
     * 
     * @param certHandle
     *            the handle of a certificate.
     * @return the handle of the private key corrisponding to the given
     *         certificate.
     * @throws PKCS11Exception
     */
    public long findSignatureKeyFromCertificateHandle(long certHandle)
            throws PKCS11Exception {

        long sessionHandle = getSession();

        if (sessionHandle < 0)
            return -1L;

        log.info("\nFind signature key from certificate with handle: "
                + certHandle);

        // first get the ID of the signature key
        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];
        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_ID;

        pkcs11Module.C_GetAttributeValue(getSession(), certHandle,
                attributeTemplateList,false);

        byte[] keyAndCertificateID = (byte[]) attributeTemplateList[0].pValue;

        log
                .debug("ID of cert: "
                        + Functions.toHexString(keyAndCertificateID));

        return findSignatureKeyFromID(keyAndCertificateID);
    }

    /**
     * Returns the DER encoded certificate corresponding to the given label, as
     * read from the token.
     * 
     * @param label
     *            the object label on the token.
     * @return the DER encoded certificate, as byte[]
     * @throws UnsupportedEncodingException
     * @throws TokenException
     */
    public byte[] getDEREncodedCertificateFromLabel(String label)
            throws TokenException {
        System.out.println("reading DER encoded certificate bytes");
        byte[] certBytes = null;

        long sessionHandle = getSession();
        if (sessionHandle < 0)
            return null;

        long certificateHandle = findCertificateFromLabel(label.toCharArray());
        certBytes = getDEREncodedCertificate(certificateHandle);

        return certBytes;
    }

    /**
     * Returns the DER encoded certificate identified by the given handle, as
     * read from the token.
     * 
     * @param certHandle
     *            the handleof the certificate on the token.
     * @return the DER encoded certificate, as a byte array.
     * @throws PKCS11Exception 
     */
    public byte[] getDEREncodedCertificate(long certHandle)
            throws PKCS11Exception {

        System.out.println("reading certificate bytes");

        byte[] certBytes = null;
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[1];
        template[0] = new CK_ATTRIBUTE();
        template[0].type = PKCS11Constants.CKA_VALUE;
        System.err.println(getSession());
        pkcs11Module.C_GetAttributeValue(getSession(), certHandle, template , false);
        certBytes = (byte[]) template[0].pValue;

        try {
			CertificateFactory cf = CertificateFactory.getInstance("X509");
		 X509Certificate mycert = 	(X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
		 System.err.println("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC---"+mycert.getIssuerDN());
			
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        
        System.err.println(new String(certBytes));
        return certBytes;
    }

 
    private byte[] getDEREncodedCertificate(long certHandle, long sessionHandle)
            throws PKCS11Exception {

        System.out.println("reading certificate bytes");

        byte[] certBytes = null;
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[1];
        template[0] = new CK_ATTRIBUTE();
        template[0].type = PKCS11Constants.CKA_VALUE;
        pkcs11Module.C_GetAttributeValue(sessionHandle, certHandle, template , false);
        certBytes = (byte[]) template[0].pValue;

        return certBytes;
    }

    /**
     * Gets the cryptoki library name.
     * 
     * @return the current cryptoki library name.
     */
    public java.lang.String getCryptokiLibrary() {
        return cryptokiLibrary;
    }


    /**
     * Gets the java wrapper for the cryptoki.
     * 
     * @return the java wrapper for the cryptoki.
     */
    private PKCS11 getPkcs11() {
        return pkcs11Module;
    }

    /*
     * public void getPrivateKey(PKCS11Helper helper, String label) {
     * 
     * PKCS11Session s = getSession(); if (s == null) return;
     * 
     * //log.info(s.getInfo() + "\n"); log.info("Getting PKCS11 Private
     * key labeled '" + label + "'..."); int[] attrtypes = { PKCS11Object.CLASS,
     * PKCS11Object.KEY_TYPE //, PKCS11Object.LABEL //gives an error
     * sometimes!!!! , PKCS11Object.ID //better method };
     * 
     * Object[] attrvalues = { PKCS11Object.PRIVATE_KEY, // CLASS
     * PKCS11Object.RSA // KEY_TYPE //,label //LABEL , label.getBytes() };
     * 
     * s.findObjectsInit(attrtypes, attrvalues); PKCS11Object rsaPrivKey = null;
     * byte[] id = null; do { rsaPrivKey = s.findObject(); if (rsaPrivKey !=
     * null) { //log.info(rsaPrivKey); id = (byte[])
     * rsaPrivKey.getAttributeValue(PKCS11Object.ID); try { log
     * .println("Private key Found:\t" + new String(id, "UTF8")); } catch
     * (java.io.UnsupportedEncodingException ueo) { log.info(ueo); } } }
     * while (rsaPrivKey != null); s.findObjectsFinal(); }
     */

    /**
     * Gets the current session handle.
     * 
     * @return the <code>long</code> identifying the current session.
     */
    public long getSession() {
        return sessionHandle;
    }

    /**
     * Finalizes PKCS#11 operations; note this NOT actually unloads the native
     * library.
     * 
     * @throws Throwable
     */
    public void libFinalize() throws Throwable {
        log.info("\nfinalizing PKCS11 module...");
        getPkcs11().finalize();
        PKCS11Manager.instance = null;
        this.isInitialized = false;        
        log.info("finalized.\n");
    }

    /**
     * Logs in to the current session; login is usually necessary to see and use
     * private key objects on the token. This method converts the given
     * <code>String</code> as a <code>char[]</code> and calls
     * {@link #login(char[])}.
     * 
     * @param pwd
     *            password as a String.
     * @throws PKCS11Exception
     */
    public void login(String pwd) throws PKCS11Exception {
        login(pwd.toCharArray());
    }

    /**
     * Logs in to the current session; login is usually necessary to see and use
     * private key objects on the token.
     * 
     * @param pwd
     *            password as a char[].
     * @throws PKCS11Exception
     */
    public void login(char[] pwd) throws PKCS11Exception {
        if (getSession() < 0)
            return;
        // log in as the normal user...

        pkcs11Module.C_Login(getSession(), PKCS11Constants.CKU_USER, pwd,false);
        log.info("\nUser logged into session.");
    }

    /**
     * Logs out the current user.
     * 
     * @throws PKCS11Exception
     */
    public void logout() throws PKCS11Exception {
        if (getSession() < 0)
            return;
        // log in as the normal user...
        pkcs11Module.C_Logout(getSession());
        log.info("\nUser logged out.\n");
    }

    /**
     * Gets currently loaded cryptoky description.
     * 
     * @throws PKCS11Exception
     */
    @SuppressWarnings("unused")
	private void getModuleInfo() throws PKCS11Exception {
        log.info("getting PKCS#11 module info");
        moduleInfo = pkcs11Module.C_GetInfo();
        log.info(moduleInfo);
    }

    /**
     * Gets current reader infos.
     * @return list of all slot IDs
     * 
     * @throws PKCS11Exception
     */
    public long[] getSlotList() throws PKCS11Exception {
        log.info("getting slot list");
        long[] slotIDs = null;
        //get all slots
        slotIDs = pkcs11Module.C_GetSlotList(false);
    //    CK_SLOT_INFO slotInfo;
        for (int i = 0; i < slotIDs.length; i++) {
            log.info("Slot Info: ");
            
            slotInfo.put(slotIDs[i], pkcs11Module.C_GetSlotInfo(slotIDs[i])) ;
            log.info(slotInfo);
        }
        return slotIDs;
    }

    /**
     * Lists currently inserted tokens and relative infos.
     * @return List of Token IDs
     * 
     * @throws PKCS11Exception
     * @throws CryptoException 
     */
    public long[] getTokenList() throws PKCS11Exception, CryptoException {
        log.info("\ngetting token list");
        long[] tokenIDs = null;
        //get only slots with a token present
        tokenIDs = pkcs11Module.C_GetSlotList(true);
        CK_TOKEN_INFO currentToken;
        log.info(tokenIDs.length + " tokens found.");
        for (int i = 0; i < tokenIDs.length; i++) {
            log.info(i + ") Info for token with handle: " + tokenIDs[i]);
            currentToken = pkcs11Module.C_GetTokenInfo(tokenIDs[i]);
            tokenInfo.put(tokenIDs[i], currentToken) ;
        }
        if (tokenIDs.length == 0){
        	throw new CryptoException(new CryptoError(GlobalErrorCode.TOKEN_NOT_DETECTED));
        }

        return tokenIDs;
    }
    
    

    /**
     * Gets informations on cryptographic operations supported by the tokens.
     * 
     * @throws PKCS11Exception
     * @throws CryptoException 
     */
    public void getMechanismInfo() throws PKCS11Exception, CryptoException {
        CK_MECHANISM_INFO mechanismInfo;

        log.info("\ngetting mechanism list...");
        long[] slotIDs = getTokenList();
        for (int i = 0; i < slotIDs.length; i++) {
            log.info("getting mechanism list for slot " + slotIDs[i]);
            long[] mechanismIDs = pkcs11Module.C_GetMechanismList(slotIDs[i]);
            for (int j = 0; j < mechanismIDs.length; j++) {
                log.info("mechanism info for mechanism id "
                        + mechanismIDs[j] + "->"
                        + Functions.mechanismCodeToString(mechanismIDs[j])
                        + ": ");
                mechanismInfo = pkcs11Module.C_GetMechanismInfo(slotIDs[i],
                        mechanismIDs[j]);
                log.info(mechanismInfo);
            }
        }

    }

    
    /**
     * @param mechanismCode
     * @return id of the token that supports specified mechanism
     * @throws PKCS11Exception
     * @throws CryptoException
     */
    protected long findSuitableToken(long mechanismCode) throws PKCS11Exception, CryptoException {
        long token = -1L;

        ArrayList<Long> tokenList = findTokensSupportingMechanism(mechanismCode);
        String mechanismString = Functions.mechanismCodeToString(mechanismCode);
        
        if (tokenList == null){
            log.info("\nSorry, no Token supports the required mechanism "
            + mechanismString + "!");
            return -1L;
        }
        
        Iterator<Long> i = tokenList.iterator();
        long currToken = -1L;        
        while (i.hasNext() && (token == -1L)) {
            currToken = ((Long) i.next()).longValue();
            log.info("\nToken with handle " + currToken
                    + " supports required mechanism " + mechanismString + ".");
            try {
                if (findCertificateWithNonRepudiationCritical(currToken) != -1L)
                    token = currToken;
            } catch (CertificateException e) {
                log.info(e);
            } catch (TokenException e) {
                log.info(e);
            }
        }

        return token;
    }

  
    protected ArrayList<Long> findTokensSupportingMechanism(long mechanismCode)
            throws PKCS11Exception, CryptoException {

        ArrayList<Long> tokenList = null;

       // String mechanismString = Functions.mechanismCodeToString(mechanismCode);

        long[] tokenIDs = getTokenList();

        for (int i = 0; i < tokenIDs.length; i++)
            if (isMechanismSupportedByToken(mechanismCode, tokenIDs[i])) {
                if (tokenList == null)
                    tokenList = new ArrayList<Long>();
                tokenList.add(new Long(tokenIDs[i]));
            }

        return tokenList;
    }

    /**
     * Queries if there is a token that supporting a given cryptographic
     * operation.
     * 
     * @param mechanismCode
     *            the ID of the required mechanism.
     * @return the handle if the token supporting the given mechanism, -1
     *         otherwise.
     * @throws PKCS11Exception
     * @throws CryptoException 
     */
    public long getTokenSupportingMechanism(long mechanismCode)
            throws PKCS11Exception, CryptoException {

        long token = -1L;

        String mechanismString = Functions.mechanismCodeToString(mechanismCode);

        long[] tokenIDs = getTokenList();

        for (int i = 0; (i < tokenIDs.length) && (token < 0); i++)
            if (isMechanismSupportedByToken(mechanismCode, tokenIDs[i]))
                token = tokenIDs[i];

        log.info((token >= 0) ? "\nToken with handle " + token
                + " supports required mechanism " + mechanismString + "."
                : "\nSorry, no Token supports the required mechanism "
                        + mechanismString + "!");

        return token;
    }

    /**
     * Tells if a given token supports a given cryptographic operation. Also
     * lists all supported mechanisms.
     * 
     * @param mechanismCode
     *            the mechanism ID.
     * @param tokenID
     *            the token handla.
     * @return <code>true</code> if the token supports the mechanism.
     * @throws PKCS11Exception
     */
    public boolean isMechanismSupportedByToken(long mechanismCode, long tokenID)
            throws PKCS11Exception {

        boolean isSupported = false;

        long[] mechanismIDs = pkcs11Module.C_GetMechanismList(tokenID);

        log.info("listing  mechanisms:");
        for (int i = 0; i < mechanismIDs.length; i++)
            log.info(mechanismIDs[i] + ": "
                    + Functions.mechanismCodeToString(mechanismIDs[i]));

        Arrays.sort(mechanismIDs);
        isSupported = Arrays.binarySearch(mechanismIDs, mechanismCode) >= 0;

        return isSupported;
    }

    /**
     * Opens a session on a specific token.
     * 
     * @param aTokenHandle
     *            the token ID.
     * @return Handler of the session of token
     * 
     * @throws TokenException
     */
    private long openSession(long aTokenHandle) throws TokenException {
        long sessionHandle = -1L;

        sessionHandle = pkcs11Module.C_OpenSession(aTokenHandle,
                PKCS11Constants.CKF_SERIAL_SESSION, null, null);

        log.info("\nSession with handle: " + sessionHandle
                + " opened on token with handle: " + aTokenHandle + " .");

        return sessionHandle;
    }

    /**
     * Opens a session on the default token.
     * @param writeAccess 
     * 
     * @throws TokenException
     */
    protected void openSession(boolean writeAccess) throws TokenException {
        long sessionHandle = -1L;
        if (getToken() >= 0) {
        	if (writeAccess)
            sessionHandle = pkcs11Module.C_OpenSession(getToken(),
                    PKCS11Constants.CKF_RW_SESSION | PKCS11Constants.CKF_SERIAL_SESSION, null, null);
        	else{
        		sessionHandle = pkcs11Module.C_OpenSession(getToken(),
                        PKCS11Constants.CKF_SERIAL_SESSION, null, null);
            	
        	}
            setSession(sessionHandle);
            log.info("\nSession opened.");

        } else {
            log.info("No token found!");
        }
    }

    /**
     * Opens a session on the token, logging in the user.
     * @param password 
     * @param writeAccess 
     * @throws TokenException
     */
    public void openSession(char[] password , boolean writeAccess) throws TokenException {
        openSession(writeAccess);
        login(password);
    }
    
    
    /**
     * @param password
     * @param newPin
     * @param tokenHandler
     * @throws CryptoException
     */
    public void changePin(String password, String newPin, long tokenHandler) throws CryptoException {
    	try {

			openSession(password.toCharArray(),true);
    	log.info("connected to token with session: "+sessionHandle);
			pkcs11Module.C_SetPIN(sessionHandle, password.toCharArray(), newPin.toCharArray(), false);
			closeSession();

    	} catch (PKCS11Exception e) {
			System.err.println(e.getErrorCode());
			System.err.println(e.getMessage());
    		if (e.getErrorCode() == CKR_PIN_INCORRECT){
				log.info("User used an invalid pin, plz check your pin");
				throw new CryptoException(new CryptoError(GlobalErrorCode.PIN_INCORRECT));
			} 
    		else if (e.getErrorCode() == CKR_PIN_LEN_RANGE){
    			throw new CryptoException(new CryptoError(GlobalErrorCode.PIN_INVALID_LENGTH));
    		}
    		else
    			throw new CryptoException(e);
		} catch (TokenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
    }

    /**
     * Sets the cryptoky library
     * 
     * @param newCryptokiLibrary
     *            the cryptoki name.
     */
    public void setCryptokiLibrary(java.lang.String newCryptokiLibrary) {
        cryptokiLibrary = newCryptokiLibrary;
    }

    /**
     * Sets the session handle.
     * 
     * @param newSession
     */
    private void setSession(long newSession) {
        this.sessionHandle = newSession;
    }

    /**
     * Gets the current token.
     * @return Returns the token handle
     * @see PKCS11Manager#initializeTokenAndMechanism
     * @see PKCS11Manager#openSession(long)
     */
    public long getToken() {
        return tokenHandle;
    }

    /**
     * Sets the current token handle.
     * 
     * @param token
     *            the token handle to set.
     */
    public void setTokenHandle(long token) {
        this.tokenHandle = token;
    }


	/**
	 * It will show you the information about the slot with the specified token
	 * <b>Note: </b> You need to call getSlotList() before this 
	 * @return the slotInfo
	 * @throws CryptoException 
	 * @see PKCS11Manager#getSlotList() 
	 */
	public HashMap<Long, CK_SLOT_INFO> getSlotInfo() throws CryptoException {
		try {
			getSlotList();
		} catch (PKCS11Exception e) {
			throw new CryptoException(e);
		}
		return slotInfo;
	}

	/**
	 * It will get the token info
	 * <b>Note: </b> You need to call getTokenList() before this 
	 * @return the tokenInfo
	 * @throws CryptoException 
	 * @see PKCS11Manager#getTokenList();
	 */
	public HashMap<Long,CK_TOKEN_INFO> getTokenInfo() throws CryptoException {
		try {
			getTokenList();
		} catch (PKCS11Exception e) {
			throw new CryptoException(e);	
		}
		return tokenInfo;
		
	}

	/**
	 * @return the isInitialized
	 */
	public boolean isInitialized() {
		return isInitialized;
	}

	/**
	 * Check if there is any token connected with the current cryptoki
	 * @return the tokenConnected
	 * @throws PKCS11Exception 
	 */
	public boolean isTokenConnected() throws PKCS11Exception {
	    log.info("\nChecking tokens");
	        long[] tokenIDs = null;
	        //get only slots with a token present
	        tokenIDs = pkcs11Module.C_GetSlotList(true);
	
	        return !(tokenIDs.length == 0);
	 }
	
}