/*
 * Copyright (c) 2014, Araz
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package tools.pki.gbay.util.general;

import java.io.UnsupportedEncodingException;

/**
 *
 * @author Araz
 */
public class Convertors {
    static final byte[] HEX_CHAR_TABLE = {(byte) '0', (byte) '1', (byte) '2',
        (byte) '3', (byte) '4', (byte) '5', (byte) '6', (byte) '7',
        (byte) '8', (byte) '9', (byte) 'a', (byte) 'b', (byte) 'c',
        (byte) 'd', (byte) 'e', (byte) 'f'};


    /**
     * 
     * @param raw
     * @param length
     * @return
     * @throws UnsupportedEncodingException 
     */
    public static String byte2HexString(byte[] raw, int length)
            throws UnsupportedEncodingException {
        byte[] hex = new byte[2 * length];
        int index = 0;

        // for (byte b : raw)
        for (int i = 0; i < length; i++) {
            byte b = raw[i];
            int v = b & 0xFF;
            hex[index++] = HEX_CHAR_TABLE[v >>> 4];
            hex[index++] = HEX_CHAR_TABLE[v & 0xF];
        }
        return (new String(hex, "ASCII")).toUpperCase();
    }
    public static byte[] stringHex2Byte(String strHex)
            throws UnsupportedEncodingException {
        byte[] bts = new byte[strHex.length() / 2];
        for (int i = 0; i < bts.length; i++) {
            bts[i] = (byte) Integer.parseInt(
                    strHex.substring(2 * i, 2 * i + 2), 16);
        }
        return bts;
    }
    
    	public static String byte2Hex(byte bytes[]) {

		char[] hexDigits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
				'a', 'b', 'c', 'd', 'e', 'f' };

		StringBuffer buf = new StringBuffer(bytes.length * 2);

		for (int i = 0; i < bytes.length; ++i) {
			buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
			buf.append(hexDigits[bytes[i] & 0x0f]);
		}

		return buf.toString();
	}

    	public static String humanReadableByteCount(long bytes, boolean si) {
    	    int unit = si ? 1000 : 1024;
    	    if (bytes < unit) return bytes + " B";
    	    int exp = (int) (Math.log(bytes) / Math.log(unit));
    	    String pre = (si ? "kMGTPE" : "KMGTPE").charAt(exp-1) + (si ? "" : "i");
    	    return String.format("%.1f %sB", bytes / Math.pow(unit, exp), pre);
    	}
    	
    	
}
