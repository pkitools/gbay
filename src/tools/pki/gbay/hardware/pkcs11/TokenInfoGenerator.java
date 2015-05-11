package tools.pki.gbay.hardware.pkcs11;

import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.wrapper.CK_TOKEN_INFO;

import java.util.HashMap;


/**
 * Generated to get the required Token information in usable Java Format
 * @author Araz
 *
 */
public class TokenInfoGenerator extends TokenInfo {
 	
	public TokenInfoGenerator(CK_TOKEN_INFO ckTokenInfo) {
		super(ckTokenInfo);	
	}


	/**
	 * Token has random generator
	 */
	public static final long  CKF_RNG                     = 0x00000001L;

    /* token is write-protected */
    public static final long  CKF_WRITE_PROTECTED         = 0x00000002L;

    /* user must login */
    public static final long  CKF_LOGIN_REQUIRED          = 0x00000004L;

    /* normal user's PIN is set */
    public static final long  CKF_USER_PIN_INITIALIZED    = 0x00000008L;

    /* CKF_RESTORE_KEY_NOT_NEEDED is new for v2.0.  If it is set,
     * that means that *every* time the state of cryptographic
     * operations of a session is successfully saved, all keys
     * needed to continue those operations are stored in the state */
    public static final long  CKF_RESTORE_KEY_NOT_NEEDED  = 0x00000020L;

    /* CKF_CLOCK_ON_TOKEN is new for v2.0.  If it is set, that means
     * that the token has some sort of clock.  The time on that
     * clock is returned in the token info structure */
    public static final long  CKF_CLOCK_ON_TOKEN          = 0x00000040L;

    /* CKF_PROTECTED_AUTHENTICATION_PATH is new for v2.0.  If it is
     * set, that means that there is some way for the user to login
     * without sending a PIN through the Cryptoki library itself */
    public static final long  CKF_PROTECTED_AUTHENTICATION_PATH = 0x00000100L;

    /* CKF_DUAL_CRYPTO_OPERATIONS is new for v2.0.  If it is true,
     * that means that a single session with the token can perform
     * dual simultaneous cryptographic operations (digest and
     * encrypt; decrypt and digest; sign and encrypt; and decrypt
     * and sign) */
    public static final long  CKF_DUAL_CRYPTO_OPERATIONS  = 0x00000200L;

    /* CKF_TOKEN_INITIALIZED if new for v2.10. If it is true, the
     * token has been initialized using C_InitializeToken or an
     * equivalent mechanism outside the scope of PKCS #11.
     * Calling C_InitializeToken when this flag is set will cause
     * the token to be reinitialized. */
    public static final long  CKF_TOKEN_INITIALIZED       = 0x00000400L;

    /* CKF_SECONDARY_AUTHENTICATION if new for v2.10. If it is
     * true, the token supports secondary authentication for
     * private key objects. */
    public static final long  CKF_SECONDARY_AUTHENTICATION  = 0x00000800L;

    /* CKF_USER_PIN_COUNT_LOW if new for v2.10. If it is true, an
     * incorrect user login PIN has been entered at least once
     * since the last successful authentication. */
    public static final long  CKF_USER_PIN_COUNT_LOW       = 0x00010000L;

    /* CKF_USER_PIN_FINAL_TRY if new for v2.10. If it is true,
     * supplying an incorrect user PIN will it to become locked. */
    public static final long  CKF_USER_PIN_FINAL_TRY       = 0x00020000L;

    /* CKF_USER_PIN_LOCKED if new for v2.10. If it is true, the
     * user PIN has been locked. User login to the token is not
     * possible. */
    public static final long  CKF_USER_PIN_LOCKED          = 0x00040000L;

    /* CKF_USER_PIN_TO_BE_CHANGED if new for v2.10. If it is true,
     * the user PIN value is the default value set by token
     * initialization or manufacturing. */
    public static final long  CKF_USER_PIN_TO_BE_CHANGED   = 0x00080000L;

    /* CKF_SO_PIN_COUNT_LOW if new for v2.10. If it is true, an
     * incorrect SO login PIN has been entered at least once since
     * the last successful authentication. */
    public static final long  CKF_SO_PIN_COUNT_LOW         = 0x00100000L;

    /* CKF_SO_PIN_FINAL_TRY if new for v2.10. If it is true,
     * supplying an incorrect SO PIN will it to become locked. */
    public static final long  CKF_SO_PIN_FINAL_TRY         = 0x00200000L;

    /* CKF_SO_PIN_LOCKED if new for v2.10. If it is true, the SO
     * PIN has been locked. SO login to the token is not possible.
     */
    public static final long  CKF_SO_PIN_LOCKED            = 0x00400000L;

    /* CKF_SO_PIN_TO_BE_CHANGED if new for v2.10. If it is true,
     * the SO PIN value is the default value set by token
     * initialization or manufacturing. */
    public static final long  CKF_SO_PIN_TO_BE_CHANGED     = 0x00800000L;
    /* Security Officer */


    public static HashMap<String, Boolean> getFlags(CK_TOKEN_INFO ck){
    	return tokenInfoFlags.toString(ck.flags);
    }
  
    /**
     * To be used later if we want to have a custom flags list
     * @param ck PKCS11 Token Info Object
     * @param flagsList list of flags {@link Flags}
     * @return
     */
    public static HashMap<String, Boolean> getFlags(CK_TOKEN_INFO ck, Flags flagsList){
    	return flagsList.toString(ck.flags);
    }
    
    
	private static final Flags tokenInfoFlags = new Flags(new long[] {
	        CKF_WRITE_PROTECTED,
	        CKF_LOGIN_REQUIRED,
	        CKF_USER_PIN_INITIALIZED,
	        CKF_TOKEN_INITIALIZED,
	        CKF_SECONDARY_AUTHENTICATION,
	        CKF_USER_PIN_COUNT_LOW,
	        CKF_USER_PIN_FINAL_TRY,
	        CKF_USER_PIN_LOCKED,
	        CKF_USER_PIN_TO_BE_CHANGED,
	        CKF_SO_PIN_COUNT_LOW,
	        CKF_SO_PIN_FINAL_TRY,
	        CKF_SO_PIN_LOCKED,
	        CKF_SO_PIN_TO_BE_CHANGED,
	    }, new String[] {
	        "Device is write protected",
	        "Login is required",
	        "User Pin is initialized",
	        "Device is Initialised",
	        "Device Supports secondary authentication",
	        "You have entered an incorrect pin",
	        "Your final try to put a correct pin",
	        "Your pin is locked",
	        "Your Pin Should be changed",
	        "You have entered an incorrect SO-Pin",
	        "Last try to enter Correct SO-PIN",
	        "SO-Pin is locked",
	        "SO-Pin should be changed",
	    });
	/**
	 * Flags used in agent
	 */
	private static final Flags allTokenInfoFlags = new Flags(new long[] {
			CKF_RNG,
			CKF_WRITE_PROTECTED,
			CKF_LOGIN_REQUIRED,
			CKF_USER_PIN_INITIALIZED,
			CKF_RESTORE_KEY_NOT_NEEDED,
			CKF_CLOCK_ON_TOKEN,
			CKF_PROTECTED_AUTHENTICATION_PATH,
			CKF_DUAL_CRYPTO_OPERATIONS,
			CKF_TOKEN_INITIALIZED,
			CKF_SECONDARY_AUTHENTICATION,
			CKF_USER_PIN_COUNT_LOW,
			CKF_USER_PIN_FINAL_TRY,
			CKF_USER_PIN_LOCKED,
			CKF_USER_PIN_TO_BE_CHANGED,
			CKF_SO_PIN_COUNT_LOW,
			CKF_SO_PIN_FINAL_TRY,
			CKF_SO_PIN_LOCKED,
			CKF_SO_PIN_TO_BE_CHANGED,
	}, new String[] {
			"Has Random Generator",
			"CKF_WRITE_PROTECTED",
			"CKF_LOGIN_REQUIRED",
			"CKF_USER_PIN_INITIALIZED",
			"CKF_RESTORE_KEY_NOT_NEEDED",
			"CKF_CLOCK_ON_TOKEN",
			"CKF_PROTECTED_AUTHENTICATION_PATH",
			"CKF_DUAL_CRYPTO_OPERATIONS",
			"CKF_TOKEN_INITIALIZED",
			"CKF_SECONDARY_AUTHENTICATION",
			"CKF_USER_PIN_COUNT_LOW",
			"CKF_USER_PIN_FINAL_TRY",
			"CKF_USER_PIN_LOCKED",
			"CKF_USER_PIN_TO_BE_CHANGED",
			"CKF_SO_PIN_COUNT_LOW",
			"CKF_SO_PIN_FINAL_TRY",
			"CKF_SO_PIN_LOCKED",
			"CKF_SO_PIN_TO_BE_CHANGED",
	});

    
	private static class Flags {
        private final long[] flagIds;
        private final String[] flagNames;
       Flags(long[] flagIds, String[] flagNames) {
            if (flagIds.length != flagNames.length) {
                throw new AssertionError("Array lengths do not match");
            }
            this.flagIds = flagIds;
            this.flagNames = flagNames;
        }
        HashMap<String, Boolean> toString(long val) {
        	HashMap<String, Boolean> sb = new HashMap<String, Boolean>();
            for (int i = 0; i < flagIds.length; i++) {
                if ((val & flagIds[i]) != 0) {
                    sb.put(flagNames[i], true);
                }
                else{
                	sb.put(flagNames[i], false);
                }
            }
            return sb;
        }
    }


}
