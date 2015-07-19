/**
 *	GBay Hardware Devices - a token and smart card managment solution (library)
 *	Copyright (c) 2014 Araz Farhang - www.pki.tools
 *
 *	

 *	
 *	This API is intended to be used by other aegis applications
 *
 *	This program is distributed in the hope that it will be useful. *

 *
 */
/*
 * $Header: /cvsroot/GBay Hardware Devices/GBay Hardware Devices/src/java/core/it/trento/comune/GBay Hardware Devices/pcsc/PCSCHelper.java,v 1.1 2004/12/27 11:14:32 resoli Exp $
 * $Date: 2004/12/27 11:14:32 $
 */

package tools.pki.gbay.hardware.pcsc;


import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import java.util.Vector;


import com.ibm.opencard.terminal.pcsc10.OCFPCSC1;
import com.ibm.opencard.terminal.pcsc10.Pcsc10Constants;
import com.ibm.opencard.terminal.pcsc10.PcscException;
import com.ibm.opencard.terminal.pcsc10.PcscReaderState;

/**
 * A java class for detecting SmartCard tokens and readers via PCSC. 
 * 
 * @author Araz Farhang
 */
public class PCSCHelper {
    private Hashtable cardInfos = new Hashtable();
    private Hashtable cards = new Hashtable();

    private String deviceListFile = "sc.properties";
    
    /** The reference to the PCSC ResourceManager for this card terminal. */
    private OCFPCSC1 pcsc;

    /** The context to the PCSC ResourceManager */
    private int context = 0;

    /** The state of this card terminal. */
    private boolean closed;

    /** Is a card inserted currently? */
    private boolean cardInserted;

    /** The cardHandle */
    private int cardHandle = 0;

    /* states returned by SCardGetStatusChange */
    private static final int SCARD_STATE_MUTE = 0x200;

    private static final int SCARD_STATE_PRESENT = 0x020;

    /** The <tt>ATR</tt> of the presently inserted card. */
    private byte[] cachedATR;

    private String type = null;

    private String[] readers = null;




    /**
     * Construct a PCSC helper
     * @param loadLib if true it will connect to the device as a PKCS#11 device
     */
    public PCSCHelper(boolean loadLib) {

        try {
        	
            System.out.println("connect to PCSC 1.0 resource manager");

            // load native library
            if(loadLib) OCFPCSC1.loadLib();

            pcsc = new OCFPCSC1();

            readers = pcsc.SCardListReaders(null);

            this.type = "PCSC10";

            /* connect to the PCSC resource manager */
            context = pcsc
                    .SCardEstablishContext(Pcsc10Constants.SCARD_SCOPE_USER);

            System.out.println("Driver initialized");

            loadProperties();

        } catch (PcscException e) {
            System.out.println(e);
        }

        /* add one slot */
        //this.addSlots(1);
    }

    private void loadProperties() {

        System.out.println("Loading properties...");

        Properties prop = new Properties();
        InputStream propertyStream;

        propertyStream = this.getClass().getResourceAsStream(deviceListFile);

        if (propertyStream != null) {
            try {
                prop.load(propertyStream);
            } catch (IOException e2) {
                System.out.println(e2);
            }
            //prop.list(System.out);
        }

        Iterator i = prop.keySet().iterator();

        String currKey = null;

        int index = 0;
        int pos = -1;
        String attribute = null;
        String value = null;

        //loading propertis in a vector of CardInfo
        Vector<CardInfo> v = new Vector<CardInfo>();
        CardInfo ci = null;
        while (i.hasNext()) {
            currKey = (String) i.next();
            pos = currKey.indexOf(".");
            index = Integer.parseInt(currKey.substring(0, pos));
            attribute = currKey.substring(pos + 1);
            value = (String) prop.get(currKey);
            value = "atr".equals(attribute) ? value.toUpperCase() : value;

            while (index > v.size()) {
                ci = new CardInfo();
                v.addElement(ci);
            }
            ci = (CardInfo) v.get(index - 1);
            ci.addProperty(attribute, value);
        }

        //coverting vector to Hashtable (keyed by ATR)
        i = v.iterator();
        while (i.hasNext()) {
            ci = (CardInfo) i.next();
            this.cardInfos.put(ci.getProperty("atr"), ci);
        }

    }

//    public static void main(String[] args) {
//
//        PCSCHelper a = new PCSCHelper(true);
//        a.findCards();
//        System.exit(0);
//
//    }

    /**
     * To get information of all connected devices
     * <b>Construct the PCSHelper with true to be able to find cards</b>
     * @return List of detail information of all connected devices
     */
    public List<CardInfo> findCards() {
        
        ArrayList<CardInfo> cards = new ArrayList<CardInfo>();
        
        try {
            int numReaders = getReaders().length;
            
            System.out.println("Found " + numReaders + " readers.");

            String currReader = null;
            for (int i = 0; i < getReaders().length; i++) {
                currReader = getReaders()[i];
                System.out.println("\nChecking card in reader '"
                        + currReader + "'.");
                if (isCardPresent(currReader)) {
                    System.out.println("Card is present in reader '"
                            + currReader + "' , ATR String follows:");
                    System.out.println("ATR: " + formatATR(cachedATR, " "));

                    CardInfo ci = (CardInfo) getCardInfos().get(
                            formatATR(cachedATR, ""));
                    
                    if (ci != null) {
                        cards.add(ci);
                        
                        System.out
                                .println("\nInformations found for this card:");
                        System.out.println("Description:\t"
                                + ci.getProperty("description"));
                        System.out.println("Manufacturer:\t"
                                + ci.getProperty("manufacturer"));
                        System.out.println("ATR:\t\t" + ci.getProperty("atr"));
                        System.out.println("Criptoki:\t"
                                + ci.getProperty("lib"));
                    }

                } else {
                    System.out.println("No card in reader '" + currReader
                            + "'!");
                }
            }

        } catch (Exception e) {
            System.out.println(e);
        }
        return cards;
    }

    /**
     * To make a friendly representative of atr
     * @param atr
     * @param byteSeparator
     * @return prettified ATR
     */
    public String formatATR(byte[] atr, String byteSeparator) {
        int n, x;
        String w = new String();
        String s = new String();

        for (n = 0; n < atr.length; n++) {
            x = (int) (0x000000FF & atr[n]);
            w = Integer.toHexString(x).toUpperCase();
            if (w.length() == 1)
                w = "0" + w;
            s = s + w + ((n + 1 == atr.length) ? "" : byteSeparator);
        } // for
        return s;
    }

    /**
     * Check whether there is a smart card present.
     * 
     * @param name 
     *            Name of the reader to check.
     * @return True if there is a smart card inserted in the card terminals
     *         slot.
     */
    public synchronized boolean isCardPresent(String name) {

        // check if terminal is already closed...
        if (!closed) {

            /* fill in the data structure for the state request */
            PcscReaderState[] rState = new PcscReaderState[1];
            rState[0] = new PcscReaderState();
            rState[0].CurrentState = Pcsc10Constants.SCARD_STATE_UNAWARE;
            rState[0].Reader = name;

            try {
                /* set the timeout to 1 second */
                pcsc.SCardGetStatusChange(context, 1, rState);

                // PTR 0219: check if a card is present but unresponsive
                if (((rState[0].EventState & SCARD_STATE_MUTE) != 0)
                        && ((rState[0].EventState & SCARD_STATE_PRESENT) != 0)) {

                    System.out
                            .println("Card present but unresponsive in reader "
                                    + name);
                }

            } catch (PcscException e) {
                System.out.println("Exception:");
                System.out.println(e);
                System.out.println("Reader " + name + " is not responsive!");
            }

            cachedATR = rState[0].ATR;

            // check the length of the returned ATR. if ATR is empty / null, no
            // card is inserted
            if (cachedATR != null) {
                if (cachedATR.length > 0)
                    return true;
                else
                    return false;
            } else
                return false;

        } else
            return false;
        // return "no card inserted", because terminal is already closed
    }

    /**
     * @return Returns the readers.
     */
    public String[] getReaders() {
        return readers;
    }

    /**
     * @return Returns the cardInfos.
     */
    public Hashtable getCardInfos() {
        return cardInfos;
    }
}