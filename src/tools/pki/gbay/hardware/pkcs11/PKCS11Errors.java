package tools.pki.gbay.hardware.pkcs11;

import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.GbayCryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;

/**
 * To convert Cryptoki error codes to GBay Standard codes 
 * @author arazfarhang
 *
 */
public class PKCS11Errors {


	 public static final int CKR_OK = 0x00000000;


    /**
     *     When a function executing in serial with an application decides to give the application a chance to do some work, it calls an application-supplied function with a CKN_SURRENDER callback . 
     *     If the callback returns the value CKR_CANCEL, then the function aborts and returns CKR_FUNCTION_CANCELED.
     */
    public static final int CKR_CANCEL = 0x00000001;
    public static final int CKR_HOST_MEMORY = 0x00000002;
    public static final int CKR_SLOT_ID_INVALID = 0x00000003;

    /* CKR_GENERAL_ERROR and CKR_FUNCTION_FAILED are new for v2.0 */
    public static final int CKR_GENERAL_ERROR = 0x00000005;
    public static final int CKR_FUNCTION_FAILED = 0x00000006;

    /*
     * CKR_ARGUMENTS_BAD, CKR_NO_EVENT, CKR_NEED_TO_CREATE_THREADS, and
     * CKR_CANT_LOCK are new for v2.01
     */
    public static final int CKR_ARGUMENTS_BAD = 0x00000007;
    public static final int CKR_NO_EVENT = 0x00000008;
    public static final int CKR_NEED_TO_CREATE_THREADS = 0x00000009;
    public static final int CKR_CANT_LOCK = 0x0000000A;
    public static final int CKR_ATTRIBUTE_READ_ONLY = 0x00000010;
    public static final int CKR_ATTRIBUTE_SENSITIVE = 0x00000011;
    public static final int CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012;
    public static final int CKR_ATTRIBUTE_VALUE_INVALID = 0x00000013;
    public static final int CKR_DATA_INVALID = 0x00000020;
    public static final int CKR_DATA_LEN_RANGE = 0x00000021;
    public static final int CKR_DEVICE_ERROR = 0x00000030;
    public static final int CKR_DEVICE_MEMORY = 0x00000031;
    public static final int CKR_DEVICE_REMOVED = 0x00000032;
    public static final int CKR_ENCRYPTED_DATA_INVALID = 0x00000040;
    public static final int CKR_ENCRYPTED_DATA_LEN_RANGE = 0x00000041;
   
    /**
     * Is called after CKR_CANCEL
     */
    public static final int CKR_FUNCTION_CANCELED = 0x00000050;
    public static final int CKR_FUNCTION_NOT_PARALLEL = 0x00000051;

    /* CKR_FUNCTION_NOT_SUPPORTED is new for v2.0 */
    public static final int CKR_FUNCTION_NOT_SUPPORTED = 0x00000054;
    public static final int CKR_KEY_HANDLE_INVALID = 0x00000060;

    /* CKR_KEY_SENSITIVE was removed for v2.0 */
    public static final int CKR_KEY_SIZE_RANGE = 0x00000062;
    public static final int CKR_KEY_TYPE_INCONSISTENT = 0x00000063;

    /*
     * CKR_KEY_NOT_NEEDED, CKR_KEY_CHANGED, CKR_KEY_NEEDED,
     * CKR_KEY_INDIGESTIBLE, CKR_KEY_FUNCTION_NOT_PERMITTED,
     * CKR_KEY_NOT_WRAPPABLE, and CKR_KEY_UNEXTRACTABLE are new for v2.0
     */
    public static final int CKR_KEY_NOT_NEEDED = 0x00000064;
    public static final int CKR_KEY_CHANGED = 0x00000065;
    public static final int CKR_KEY_NEEDED = 0x00000066;
    public static final int CKR_KEY_INDIGESTIBLE = 0x00000067;
    public static final int CKR_KEY_FUNCTION_NOT_PERMITTED = 0x00000068;
    public static final int CKR_KEY_NOT_WRAPPABLE = 0x00000069;
    public static final int CKR_KEY_UNEXTRACTABLE = 0x0000006A;
    public static final int CKR_MECHANISM_INVALID = 0x00000070;
    public static final int CKR_MECHANISM_PARAM_INVALID = 0x00000071;

    /*
     * CKR_OBJECT_CLASS_INCONSISTENT and CKR_OBJECT_CLASS_INVALID were removed
     * for v2.0
     */
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

    /*
     * CKR_SESSION_READ_ONLY_EXISTS and CKR_SESSION_READ_WRITE_SO_EXISTS are new
     * for v2.0
     */
    public static final int CKR_SESSION_READ_ONLY_EXISTS = 0x000000B7;
    public static final int CKR_SESSION_READ_WRITE_SO_EXISTS = 0x000000B8;
    public static final int CKR_SIGNATURE_INVALID = 0x000000C0;
    public static final int CKR_SIGNATURE_LEN_RANGE = 0x000000C1;
    public static final int CKR_TEMPLATE_INCOMPLETE = 0x000000D0;
    public static final int CKR_TEMPLATE_INCONSISTENT = 0x000000D1;
    public static final int CKR_TOKEN_NOT_PRESENT = 0x000000E0;
    public static final int CKR_TOKEN_NOT_RECOGNIZED = 0x000000E1;
    public static final int CKR_TOKEN_WRITE_PROTECTED = 0x000000E2;
    public static final int CKR_UNWRAPPING_KEY_HANDLE_INVALID = 0x000000F0;
    public static final int CKR_UNWRAPPING_KEY_SIZE_RANGE = 0x000000F1;
    public static final int CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = 0x000000F2;
    public static final int CKR_USER_ALREADY_LOGGED_IN = 0x00000100;
    public static final int CKR_USER_NOT_LOGGED_IN = 0x00000101;
    public static final int CKR_USER_PIN_NOT_INITIALIZED = 0x00000102;
    public static final int CKR_USER_TYPE_INVALID = 0x00000103;

    /*
     * CKR_USER_ANOTHER_ALREADY_LOGGED_IN and CKR_USER_TOO_MANY_TYPES are new to
     * v2.01
     */
    public static final int CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 0x00000104;
    public static final int CKR_USER_TOO_MANY_TYPES = 0x00000105;
    public static final int CKR_WRAPPED_KEY_INVALID = 0x00000110;
    public static final int CKR_WRAPPED_KEY_LEN_RANGE = 0x00000112;
    public static final int CKR_WRAPPING_KEY_HANDLE_INVALID = 0x00000113;
    public static final int CKR_WRAPPING_KEY_SIZE_RANGE = 0x00000114;
    public static final int CKR_WRAPPING_KEY_TYPE_INCONSISTENT = 0x00000115;
    public static final int CKR_RANDOM_SEED_NOT_SUPPORTED = 0x00000120;

    /* These are new to v2.0 */
    public static final int CKR_RANDOM_NO_RNG = 0x00000121;

    /* These are new to v2.11 */
    public static final int CKR_DOMAIN_PARAMS_INVALID = 0x00000130;

    /* These are new to v2.0 */
    public static final int CKR_BUFFER_TOO_SMALL = 0x00000150;
    public static final int CKR_SAVED_STATE_INVALID = 0x00000160;
    public static final int CKR_INFORMATION_SENSITIVE = 0x00000170;
    public static final int CKR_STATE_UNSAVEABLE = 0x00000180;

    /* These are new to v2.01 */
    public static final int CKR_CRYPTOKI_NOT_INITIALIZED = 0x00000190;
    public static final int CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191;
    public static final int CKR_MUTEX_BAD = 0x000001A0;
    public static final int CKR_MUTEX_NOT_LOCKED = 0x000001A1;

    /* This is new to v2.20 */
    public static final int CKR_FUNCTION_REJECTED = 0x00000200;

    //TODO : map all pkcs11 errors with aegis exception
    
    static public GbayCryptoException getCryptoError(PKCS11Exception errorCode)
    {
    	
            switch ((int)errorCode.getErrorCode())
            {
            case CKR_OK:                                return new GbayCryptoException(new CryptoError(GlobalErrorCode.TXN_SUCCESS));
            case CKR_CANCEL:                            return new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_OPERATION_CANCEL));
            case CKR_SLOT_ID_INVALID:                   return new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_INVALID_SLOT));
            case CKR_GENERAL_ERROR:                     return new GbayCryptoException(new CryptoError(GlobalErrorCode.TXN_FAIL));
        //    case CKR_FUNCTION_FAILED:                   return "CKR_FUNCTION_FAILED";
            case CKR_ARGUMENTS_BAD:                     return new GbayCryptoException(new CryptoError(GlobalErrorCode.REQ_PARAMETER_FAILED));
//            case CKR_NO_EVENT:                          return "CKR_NO_EVENT";
  //          case CKR_NEED_TO_CREATE_THREADS:            return "CKR_NEED_TO_CREATE_THREADS";
   //         case CKR_CANT_LOCK:                         return "CKR_CANT_LOCK";
    //        case CKR_ATTRIBUTE_READ_ONLY:               return "CKR_ATTRIBUTE_READ_ONLY";
     //       case CKR_ATTRIBUTE_SENSITIVE:               return "CKR_ATTRIBUTE_SENSITIVE";
      //      case CKR_ATTRIBUTE_TYPE_INVALID:            return "CKR_ATTRIBUTE_TYPE_INVALID";
       //     case CKR_ATTRIBUTE_VALUE_INVALID:           return "CKR_ATTRIBUTE_VALUE_INVALID";
       //     case CKR_DATA_INVALID:                      return "CKR_DATA_INVALID";
           case CKR_DATA_LEN_RANGE:                    return new GbayCryptoException(new CryptoError(GlobalErrorCode.ENTITY_INVALID_LENGTH));
            case CKR_DEVICE_ERROR:                    return new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_ERR_LOAD_LIBRARY));
 //           case CKR_DEVICE_MEMORY:                     return "CKR_DEVICE_MEMORY";
            case CKR_DEVICE_REMOVED:                    return new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_NOT_DETECTED));
  //          case CKR_ENCRYPTED_DATA_INVALID:            return "CKR_ENCRYPTED_DATA_INVALID";
   //         case CKR_ENCRYPTED_DATA_LEN_RANGE:          return "CKR_ENCRYPTED_DATA_LEN_RANGE";
    //        case CKR_FUNCTION_CANCELED:                 return "CKR_FUNCTION_CANCELED";
    //        case CKR_FUNCTION_NOT_PARALLEL:             return "CKR_FUNCTION_NOT_PARALLEL";
     //       case CKR_FUNCTION_NOT_SUPPORTED:            return "CKR_FUNCTION_NOT_SUPPORTED";
     /*       case CKR_KEY_HANDLE_INVALID:                return "CKR_KEY_HANDLE_INVALID";
            case CKR_KEY_SIZE_RANGE:                   new CryptoException(new CryptoError(GlobalErrorCode.ERR_INVALID_PARAMETER));
            case CKR_KEY_TYPE_INCONSISTENT:             new CryptoException(new CryptoError(GlobalErrorCode.ERR_INVALID_PARAMETER));
            case CKR_KEY_NOT_NEEDED:                    return "CKR_KEY_NOT_NEEDED";
            case CKR_KEY_CHANGED:                       return "CKR_KEY_CHANGED";
            case CKR_KEY_NEEDED:                        return "CKR_KEY_NEEDED";
            case CKR_KEY_INDIGESTIBLE:                  return "CKR_KEY_INDIGESTIBLE";
            case CKR_KEY_FUNCTION_NOT_PERMITTED:        return "CKR_KEY_FUNCTION_NOT_PERMITTED";
            case CKR_KEY_NOT_WRAPPABLE:                 return "CKR_KEY_NOT_WRAPPABLE";
            case CKR_KEY_UNEXTRACTABLE:                 return "CKR_KEY_UNEXTRACTABLE";
            */
            case CKR_MECHANISM_INVALID:                 new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_GET_ATTRIBUTE_FAIL));
  //          case CKR_MECHANISM_PARAM_INVALID:           return "CKR_MECHANISM_PARAM_INVALID";
    //        case CKR_OBJECT_HANDLE_INVALID:             return "CKR_OBJECT_HANDLE_INVALID";
     //       case CKR_OPERATION_ACTIVE:                  return "CKR_OPERATION_ACTIVE";
      //      case CKR_OPERATION_NOT_INITIALIZED:         return "CKR_OPERATION_NOT_INITIALIZED";
            case CKR_PIN_INCORRECT:                     return new GbayCryptoException(new CryptoError(GlobalErrorCode.PIN_INCORRECT));
            case CKR_PIN_INVALID:                       return new GbayCryptoException(new CryptoError(GlobalErrorCode.PIN_INVALID_FORMAT));
            case CKR_PIN_LEN_RANGE:                     return new GbayCryptoException(new CryptoError(GlobalErrorCode.PIN_INVALID_LENGTH));
            case CKR_PIN_EXPIRED:                       return new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_INVALID_LOGIN_TYPE));
            case CKR_PIN_LOCKED:                        return new GbayCryptoException(new CryptoError(GlobalErrorCode.PIN_LOCKED));
            case CKR_SESSION_CLOSED:                    return new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_INVALID_SESSION_ID));
            case CKR_SESSION_COUNT:                     return new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_INVALID_SESSION_ID));
            case CKR_SESSION_HANDLE_INVALID:            return new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_INVALID_SESSION_ID));
            case CKR_SESSION_PARALLEL_NOT_SUPPORTED:    return new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_INVALID_SESSION_ID));
            case CKR_SESSION_READ_ONLY:                 return new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_INVALID_SESSION_ID));
            case CKR_SESSION_EXISTS:                    return new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_INVALID_SESSION_ID));
            case CKR_SESSION_READ_ONLY_EXISTS:          return new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_INVALID_SESSION_ID));
            case CKR_SESSION_READ_WRITE_SO_EXISTS:      return new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_INVALID_SESSION_ID));
            case CKR_SIGNATURE_INVALID:                 return new GbayCryptoException(new CryptoError(GlobalErrorCode.SIG_INVALID));
            case CKR_SIGNATURE_LEN_RANGE:               return new GbayCryptoException(new CryptoError(GlobalErrorCode.ENTITY_INVALID_LENGTH));
//            case CKR_TEMPLATE_INCOMPLETE:               return "CKR_TEMPLATE_INCOMPLETE";
 //           case CKR_TEMPLATE_INCONSISTENT:             return "CKR_TEMPLATE_INCONSISTENT";
            case CKR_TOKEN_NOT_PRESENT:                 return new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_NOT_INSIDE));
            case CKR_TOKEN_NOT_RECOGNIZED:              return new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_NOT_DETECTED));
//            case CKR_TOKEN_WRITE_PROTECTED:             return "CKR_TOKEN_WRITE_PROTECTED";
  //          case CKR_UNWRAPPING_KEY_HANDLE_INVALID:     return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
   //         case CKR_UNWRAPPING_KEY_SIZE_RANGE:         return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
    //        case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:  return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
            case CKR_USER_ALREADY_LOGGED_IN:            return new GbayCryptoException(new CryptoError(GlobalErrorCode.REQ_ALREADY_LOGED_IN));
            case CKR_USER_NOT_LOGGED_IN:                return new GbayCryptoException(new CryptoError(GlobalErrorCode.REQ_LOGIN_NEEDED));
            case CKR_USER_PIN_NOT_INITIALIZED:          return new GbayCryptoException(new CryptoError(GlobalErrorCode.PIN_NEEDED));
          /*  case CKR_USER_TYPE_INVALID:                 return "CKR_USER_TYPE_INVALID";
            case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:    return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
            case CKR_USER_TOO_MANY_TYPES:               return "CKR_USER_TOO_MANY_TYPES";
            case CKR_WRAPPED_KEY_INVALID:               return "CKR_WRAPPED_KEY_INVALID";
            case CKR_WRAPPED_KEY_LEN_RANGE:             return "CKR_WRAPPED_KEY_LEN_RANGE";
            case CKR_WRAPPING_KEY_HANDLE_INVALID:       return "CKR_WRAPPING_KEY_HANDLE_INVALID";
            case CKR_WRAPPING_KEY_SIZE_RANGE:           return "CKR_WRAPPING_KEY_SIZE_RANGE";
            case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:    return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
            case CKR_RANDOM_SEED_NOT_SUPPORTED:         return "CKR_RANDOM_SEED_NOT_SUPPORTED";
            case CKR_RANDOM_NO_RNG:                     return "CKR_RANDOM_NO_RNG";
            case CKR_DOMAIN_PARAMS_INVALID:             return "CKR_DOMAIN_PARAMS_INVALID";
            case CKR_BUFFER_TOO_SMALL:                  return "CKR_BUFFER_TOO_SMALL";
            case CKR_SAVED_STATE_INVALID:               return "CKR_SAVED_STATE_INVALID";
            case CKR_INFORMATION_SENSITIVE:             return "CKR_INFORMATION_SENSITIVE";
            case CKR_STATE_UNSAVEABLE:                  return "CKR_STATE_UNSAVEABLE";*/
            case CKR_CRYPTOKI_NOT_INITIALIZED:          return new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_PKI_NOTINITIALISE));
            case CKR_CRYPTOKI_ALREADY_INITIALIZED:      return new GbayCryptoException(new CryptoError(GlobalErrorCode.TOKEN_PKI_NOTINITIALISE));
//            case CKR_MUTEX_BAD:                         return "CKR_MUTEX_BAD";
 //           case CKR_MUTEX_NOT_LOCKED:                  return "CKR_MUTEX_NOT_LOCKED";
  //          case CKR_FUNCTION_REJECTED:                 return "CKR_FUNCTION_REJECTED";*/
            default:                                    return new GbayCryptoException(GlobalErrorCode.TXN_FAIL);
            
            }
    } 

}
