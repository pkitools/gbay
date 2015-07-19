package tools.pki.gbay.hardware.pkcs11;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;





import tools.pki.gbay.errors.CryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;
import tools.pki.gbay.hardware.pcsc.CardInfo;
import tools.pki.gbay.hardware.pcsc.PCSCHelper;
import tools.pki.gbay.hardware.provider.PKCS11Manager;
import iaik.pkcs.pkcs11.TokenException;

/**
 * To detect connected devices
 * @author Android
 *
 */
public class DeviceDetector {

    /**
     * The <code>Log4j</code> where logging messages are written.
     *  
     */
	private static Logger log = Logger.getLogger(DeviceDetector.class);
    
	List<CardInfo> conectedCardsList = new ArrayList<CardInfo>();
	int cardsNo;

	/**
	 * To check if any of cards in the provided list is connected 
	 * @param candidates List of devices
	 * @return List of connected cards
	 * @throws CryptoException
	 */
	public static List<CardInfo> detectCardAndCriptoki(List<CardInfo> candidates) throws CryptoException {
		 List<CardInfo> cards = new ArrayList<CardInfo>();
		
		for (CardInfo ci : candidates){
			PKCS11Manager manager ;
			try{
				 manager = PKCS11Manager.getInstance(ci.getProperty("lib"));
				if (manager.isTokenConnected()){
					
					//Card is inside
					cards.add(ci);

					log.debug("FOUND");	
				}
				manager.libFinalize();
					
			} catch (CryptoException | IOException | TokenException e) {
					
					if (e instanceof CryptoException){
						if (((CryptoException) e).getErrorCode() == GlobalErrorCode.TOKEN_NOT_DETECTED.id)
							log.info(((CryptoException) e).getErrorCode());
					}
					log.error(e);

			} catch (Throwable e) {
			
				log.error(e);
			}
	//		finally{
		//		try {
//					PKCS11Manager.dispose();
			//	} catch (Throwable e) {
					// TODO Auto-generated catch block
		//			e.printStackTrace();
			//	}
			//}
			
		}

		
		
		//boolean cardPresent = false;

		PCSCHelper pcsc = new PCSCHelper(true);

		  cards.addAll( pcsc.findCards());

		return cards;
	}


	
	/*
 final Logger log = Logger.getLogger(DeviceDetector.class);
	List<CardInfo> conectedCardsList = new ArrayList<CardInfo>();
	  /**
     * The java object wrapping criptoki library functionalities.
     */
//    private PKCS11 pkcs11Module = null;


	/**
     * Queries if there is a token that supporting a given cryptographic
     * operation.
     * 
     * @param mechanismCode
     *            the ID of the required mechanism.
     * @return the handle if the token supporting the given mechanism, -1
     *         otherwise.
     * @throws PKCS11Exception
     */
  /*  public long getTokenSupportingMechanism(long mechanismCode)
            throws PKCS11Exception {

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
     * Lists currently inserted tokens and relative infos.
     * 
     * @throws PKCS11Exception
     *
    private long[] getTokenList() throws PKCS11Exception {
        log.info("\ngetting token list");
        long[] tokenIDs = null;
        //get only slots with a token present
        tokenIDs = pkcs11Module.C_GetSlotList(true);
        CK_TOKEN_INFO tokenInfo;
        log.info(tokenIDs.length + " tokens found.");
        for (int i = 0; i < tokenIDs.length; i++) {
            log.info(i + ") Info for token with handle: " + tokenIDs[i]);
            tokenInfo = pkcs11Module.C_GetTokenInfo(tokenIDs[i]);
            log.info(tokenInfo);
        }

        return tokenIDs;
    }

    /**
     * Gets informations on cryptographic operations supported by the tokens.
     * 
     * @throws PKCS11Exception
     *
    public void getMechanismInfo() throws PKCS11Exception {
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

    
    public long findSuitableToken(long mechanismCode) throws PKCS11Exception {
        long token = -1L;

        ArrayList tokenList = findTokensSupportingMechanism(mechanismCode);
        String mechanismString = Functions.mechanismCodeToString(mechanismCode);
        
        if (tokenList == null){
            log.info("\nSorry, no Token supports the required mechanism "
            + mechanismString + "!");
            return -1L;
        }
        
        Iterator i = tokenList.iterator();
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

    public ArrayList findTokensSupportingMechanism(long mechanismCode)
            throws PKCS11Exception {

        ArrayList tokenList = null;

        String mechanismString = Functions.mechanismCodeToString(mechanismCode);

        long[] tokenIDs = getTokenList();

        for (int i = 0; i < tokenIDs.length; i++)
            if (isMechanismSupportedByToken(mechanismCode, tokenIDs[i])) {
                if (tokenList == null)
                    tokenList = new ArrayList();
                tokenList.add(new Long(tokenIDs[i]));
            }

        return tokenList;
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
     *
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
     *
    public long findCertificateWithNonRepudiationCritical()
            throws TokenException, CertificateException {

        long certKeyHandle = -1L;

        if (getSession() < 0)
            return -1L;

        log
                .println("finding a certificate with Critical KeyUsage including non repudiation ...");

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

}*/
}