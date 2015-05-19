package tools.pki.gbay.crypto.keys.der;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import tools.pki.gbay.errors.CryptoException;

public class DERValue implements DER
{

  // Fields.
  // ------------------------------------------------------------------------

  private final int tagClass;
  private final boolean constructed;
  private final int tag;
  private int length;
  private final Object value;
  private byte[] encoded;

  // Constructor.
  // ------------------------------------------------------------------------

  public DERValue(int tag, int length, Object value, byte[] encoded)
  {
    tagClass = tag & 0xC0;
    this.tag = tag & 0x1F;
    constructed = (tag & CONSTRUCTED) == CONSTRUCTED;
    this.length = length;
    this.value = value;
    if (encoded != null)
      this.encoded = (byte[]) encoded.clone();
  }

  public DERValue(int tag, Object value)
  {
    this(tag, 0, value, null);
  }

  // Instance methods.
  // ------------------------------------------------------------------------

  public int getExternalTag()
  {
    return tagClass | tag | (constructed ? 0x20 : 0x00);
  }

  public int getTag()
  {
    return tag;
  }

  public int getTagClass()
  {
    return tagClass;
  }

  public boolean isConstructed()
  {
    return constructed;
  }

  public int getLength() throws CryptoException
  {
    if (encoded == null)
      {
        try
          {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            length = DERWriter.write(out, this);
            encoded = out.toByteArray();
          }
        catch (IOException ioe)
          {
            IllegalArgumentException iae = new IllegalArgumentException ();
            iae.initCause (ioe);
            throw iae;
          }
      }
    return length;
  }

  public Object getValue()
  {
    return value;
  }

  public Object getValueAs (final int derType) throws IOException, CryptoException
  {
    byte[] encoded = getEncoded ();
    encoded[0] = (byte) derType;
    return DERReader.read (encoded).getValue ();
  }

  public byte[] getEncoded() throws CryptoException
  {
    if (encoded == null)
      {
        try
          {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            length = DERWriter.write(out, this);
            encoded = out.toByteArray();
          }
        catch (IOException ioe)
          {
            IllegalArgumentException iae = new IllegalArgumentException ();
            iae.initCause (ioe);
            throw iae;
          }
      }
    return (byte[]) encoded.clone();
  }

  public int getEncodedLength() throws CryptoException
  {
    if (encoded == null)
      {
        try
          {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            length = DERWriter.write(out, this);
            encoded = out.toByteArray();
          }
        catch (IOException ioe)
          {
            IllegalArgumentException iae = new IllegalArgumentException ();
            iae.initCause (ioe);
            throw iae;
          }
      }
    return encoded.length;
  }

  public String toString()
  {
    String start = "DERValue ( [";
    if (tagClass == DER.UNIVERSAL) 
      start = start + "UNIVERSAL ";
    else if (tagClass == DER.PRIVATE) 
      start = start + "PRIVATE ";
    else if (tagClass == DER.APPLICATION) 
      start = start + "APPLICATION ";
    start = start + tag + "] constructed=" + constructed + ", value=";
    if (constructed)
		try {
			start = start + "\n" + Util.hexDump(getEncoded(), "\t");
		} catch (CryptoException e) {
			e.printStackTrace();
		}
	else
     start = start + value;
    return start + " )";
  }
}