package tools.pki.gbay.hardware.pkcs11;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;

import java.io.IOException;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;

import org.apache.log4j.Logger;

import tools.pki.gbay.configuration.SecurityConcepts;
import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.CryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;

/**
 * Connection to PKCS#11 device
 * @author Android
 *
 */
public class Connection {
	static Logger log = Logger.getLogger(Connection.class);

	/**
	 * Check if a mechanism is supported by a specified  {@link Token}}
	 * @param token
	 * @param mechanism
	 * @return true if supported
	 * @throws TokenException
	 */
	public static boolean isMechanismSupported(Token token, Long mechanism)
			throws TokenException {

		List<Mechanism> supportedMechanisms = Arrays.asList(token.getMechanismList());
		log.info("Token supports " + supportedMechanisms.size()
				+ "Mechanisms : " + supportedMechanisms.toString());
		// check, if the token supports the required mechanism
		if (supportedMechanisms.contains(Mechanism.get(mechanism))) {
			log.info("Mechanism with code  " + mechanism
					+ " is supported by token");
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Lists all available tokens of the given module and lets the user select
	 * one, if there is more than one available. Supports token preselection.
	 * 
	 * @param pkcs11Module
	 *            The PKCS#11 module to use.
	 * @param tokenDetectionListener object to be called upon detection of a device
	 * @param mechanism 
	 * @return The selected token or null, if no token is available or the user
	 *         canceled the action.
	 * @throws TokenException
	 * @throws CryptoException
	 * @preconditions (pkcs11Module <> null) and (output <> null) and (input <>
	 *                null)
	 * @postconditions
	 */

	public static Token selectToken(Module pkcs11Module,
			TokenFinderInterFace tokenDetectionListener, long mechanism)
			throws TokenException, CryptoException {
		// Hashtable tokenList = null;

		if (pkcs11Module == null) {
			throw new NullPointerException(
					"Argument \"pkcs11Module\" must not be null.");
		}

		log.debug(SecurityConcepts.StarLine);
		log.debug("getting list of all tokens");
		Slot[] slotsWithToken = pkcs11Module
				.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
		Token[] tokens = new Token[slotsWithToken.length];
		Hashtable tokenIDtoToken = new Hashtable(tokens.length);
		// tokenList = new Hashtable<Long, Token>();
		for (int i = 0; i < slotsWithToken.length; i++) {
			log.debug(SecurityConcepts.StarLine + "Number of slots with token: "
					+ slotsWithToken.length);
			if (mechanism == -1L) {
				log.info("No mechanism is specified");
				tokens[i] = slotsWithToken[i].getToken();
			} else if (isMechanismSupported(slotsWithToken[i].getToken(),
					mechanism))
				tokens[i] = slotsWithToken[i].getToken();
		}
		Token token = null;
		Long selectedTokenID = null;
		if (tokens.length == 0) {
			throw new CryptoException(new CryptoError(
					GlobalErrorCode.TOKEN_NOT_DETECTED));
		} else if (tokens.length == 1) {
			selectedTokenID = new Long(tokens[0].getTokenID());
			token = tokens[0];
		} else if (tokenDetectionListener == null) {
			token = tokens[0];
		} else {
			boolean gotTokenID = false;
			while (!gotTokenID) {
				try {

					try {
						selectedTokenID = tokenDetectionListener
								.selectToken(tokens);
					} catch (Exception e) {
						throw new CryptoException(new CryptoError(
								GlobalErrorCode.ENTITY_INCORRECT_FORMAT));

					}
					token = (Token) tokenIDtoToken.get(selectedTokenID);
					if (token != null) {
						gotTokenID = true;
					} else {
						log.debug("A token with the entered ID \""
								+ selectedTokenID
								+ "\" does not exist. Try again.");
					}
				} catch (NumberFormatException ex) {
					log.debug("The entered ID \"" + selectedTokenID
							+ "\" is invalid. Try again.");
				}
			}
		}

		return token;
	}

	/**
	 * Opens an authorized session for the given token. If the token requires
	 * the user to login for private operations, the method loggs in the user.
	 *
	 * @param token
	 *            The token to open a session for.
	 * @param rwSession
	 *            If the session should be a read-write session. This may be
	 *            Token.SessionReadWriteBehavior.RO_SESSION or
	 *            Token.SessionReadWriteBehavior.RW_SESSION.
	 * @return The selected token or null, if no token is available or the user
	 *         canceled the action.
	 * @exception TokenException
	 *                If listing the tokens failed.
	 * @exception IOException
	 *                If writing a user prompt faild or if reading user input
	 *                failed.
	 * @preconditions (token <> null) and (output <> null) and (input <> null)
	 * @postconditions (result <> null)
	 */
	public static Session openAuthorizedSession(Token token, boolean rwSession)
			throws TokenException, IOException {
		return openAuthorizedSession(token, rwSession, null);
	}

	/**
	 * Opens an authorized session for the given token. If the token requires
	 * the user to login for private operations, the method loggs in the user.
	 *
	 * @param token
	 *            The token to open a session for.
	 * @param rwSession
	 *            If the session should be a read-write session. This may be
	 *            Token.SessionReadWriteBehavior.RO_SESSION or
	 *            Token.SessionReadWriteBehavior.RW_SESSION.
	 * @param pin pin of device
	 * @return The selected token or null, if no token is available or the user
	 *         canceled the action.
	 * @exception TokenException
	 *                If listing the tokens failed.
	 * @exception IOException
	 *                If writing a user prompt faild or if reading user input
	 *                failed.
	 * @preconditions (token <> null) and (output <> null) and (input <> null)
	 * @postconditions (result <> null)
	 */
	public static Session openAuthorizedSession(Token token, boolean rwSession,
			String pin) throws TokenException, IOException {
		if (token == null) {
			throw new NullPointerException(
					"Argument \"token\" must not be null.");
		}

		log.info("opening session");
		Session session = token.openSession(Token.SessionType.SERIAL_SESSION,
				rwSession, null, null);

		TokenInfo tokenInfo = token.getTokenInfo();
		if (tokenInfo.isLoginRequired()) {
			session.login(Session.UserType.USER, pin.toCharArray());
		}
		return session;
	}

}
