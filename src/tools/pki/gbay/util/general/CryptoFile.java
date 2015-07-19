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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import tools.pki.gbay.crypto.texts.PlainText;
import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.CryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;

import org.apache.log4j.Logger;

/**
 * Note: When you construct an CryptoFile Object it automatically reads the file unless you construct for output
 * @author Araz
 */
public class CryptoFile implements FileInterface{
Logger log = Logger.getLogger(CryptoFile.class);
    private PlainText content;
	private char[] pin;
	//private File file;
	private FileLocation place;
	private String path;
    private OpenMode mode;
	public enum OpenMode{
		read,write,both;
	}
	
	
	
	public enum FileLocation{
		PROJECT_FOLDER,
		RELATIVE_PATH,
		RELATIVE_TOJAR,
		INSIDE_JAR,
		ABSOLOUT_PATH;
	}
	
	protected void setContentFromFile() throws CryptoException{
		  try {
			  log.debug("Reading file: " + path);
	  			this.content = new PlainText(FileUtil.getDataFromFile(path)) ;
	  			log.info(path + " was read successfully.");
	  		} catch (IOException e) {
	  			log.error(path + ", could not be oppened");
	  			throw new CryptoException(new CryptoError(GlobalErrorCode.FILE_IO_ERROR));			
	  		}
	}
	
	
	protected void setContentFromResource() throws CryptoException{
		this.content = new PlainText(FileUtil.loadText(path)) ;
	}
	
	public CryptoFile(File file) throws CryptoException {
//		this.file = file;
		this.path = file.getAbsolutePath();
		  setContentFromFile();
		  setMode(OpenMode.read);
	}
	public CryptoFile(File file, String pin) throws CryptoException {
		this(file);
		this.pin = pin.toCharArray();
	}
	
	public CryptoFile(byte[] content, String pin)  {
		 setContent(content);
		this.pin = pin.toCharArray();
	}
	
    public CryptoFile(byte[] content, String outputAddress, OpenMode mode) throws CryptoException{
    	setMode(mode);
    	this.path = outputAddress;
//    	file = new File(outputAddress);
    	this.content = new PlainText(content);
    	
    	if (mode == OpenMode.write){
    	try {
			write();
		} catch (IOException e) {
			throw new CryptoException(new CryptoError(GlobalErrorCode.FILE_IO_ERROR));
		}
    	}
    }

    public CryptoFile(byte[] content, String outputAddress, String pin) throws CryptoException{
    	this(content,outputAddress);
    	this.pin = pin.toCharArray();
    }
    
    /**
     * @throws CryptoException 
     * Write an inputStream to a file
     * @param inputStream
     * @param outputStream
     * @throws  
     */
    public CryptoFile(InputStream inputStream, String address)  {
   // 	file = new File(address);
    path = address;
    	setMode(OpenMode.both);
    	OutputStream outputStream = null;
		try {
     
    		// write the inputStream to a FileOutputStream
    		outputStream = 
                        new FileOutputStream(new File(address));
     
    		int read = 0;
    		byte[] bytes = new byte[1024];
     
    		while ((read = inputStream.read(bytes)) != -1) {
    			outputStream.write(bytes, 0, read);
    		}
     
    		log.debug("Done!");
     
    	} catch (IOException e) {
    		e.printStackTrace();
    	} finally {
    		if (inputStream != null) {
    			try {
    				inputStream.close();
    			} catch (IOException e) {
    				e.printStackTrace();
    			}
    		}
    		if (outputStream != null) {
    			try {
    				// outputStream.flush();
    				outputStream.close();
    			} catch (IOException e) {
    				e.printStackTrace();
    			}
     
    		}
    	}    
    }
    
    
    public CryptoFile(String fileAddress ) throws CryptoException {
    this(new File(fileAddress));
   }
    
    public CryptoFile(String fileAddress,String pin , FileLocation fileAddressType ) throws CryptoException {
    	setMode(OpenMode.read);
    	if (fileAddressType == FileLocation.PROJECT_FOLDER){
      	path = getClass().getClassLoader().getResource(".").getPath() + fileAddress;
      //	file = new File(path);
      	setContentFromFile();
      	
      	}
      	else if (fileAddressType == FileLocation.RELATIVE_PATH || fileAddressType == FileLocation.ABSOLOUT_PATH){
      	//	file = new File(fileAddress);
         path = fileAddress;
      		setContentFromFile();

         }
      	else if (fileAddressType == FileLocation.RELATIVE_TOJAR){
      		 File jarPath=new File(CryptoFile.class.getProtectionDomain().getCodeSource().getLocation().getPath());
             path=jarPath.getParentFile().getAbsolutePath()+ fileAddress;
            // file = new File(path );
           	setContentFromFile();

      	}
      	else if (fileAddressType == FileLocation.INSIDE_JAR){
      		path = fileAddress;
      		setContentFromResource();
      	}
      	
    	this.pin = pin.toCharArray();
    }
 
    public CryptoFile(String fileAddress, String pin) throws CryptoException {
    	this(fileAddress,pin,FileLocation.RELATIVE_PATH);
	}


	public byte[] read() throws IOException {
    return FileUtil.getDataFromFile(path);
  }

  
  /* (non-Javadoc)
 * @see tools.pki.gbay.util.general.FileInterface#write()
 */
@Override
public void write() throws IOException{
      writeFile(content.toByte());
  }
  
  // Write byte array to a file
  protected void writeFile( byte data[] )
      throws IOException {
    FileOutputStream fout = new FileOutputStream( path);
    fout.write( data );
    fout.close();
  }

    /* (non-Javadoc)
	 * @see tools.pki.gbay.util.general.FileInterface#toByte()
	 */
    @Override
	public byte[] toByte() {
        return content.toByte();
    }
    
    public PlainText toPlainText() {
		return this.content;
	}
    

    /**
     * @param content the content to set
     */
    public void setContent(byte[] data) {
        this.content =  new PlainText(data);
    }
    
    public OutputStream getOutPutStream() throws CryptoException{
    	OutputStream fop;
    	try {
			 fop = new FileOutputStream(new File( path));
		} catch (FileNotFoundException e) {
			throw new CryptoException(new CryptoError(GlobalErrorCode.FILE_NOT_FOUND));
		}
    	return fop;
    }
    
    public FileInputStream toFileInputStream() throws CryptoException{
    	try {
			return new FileInputStream(path);
		} catch (FileNotFoundException e) {
			throw new CryptoException(new CryptoError(GlobalErrorCode.FILE_NOT_FOUND));

		}
    }

	/**
	 * @return the pin
	 */
	public char[] getPin() {
		return pin;
	}

	/**
	 * @param pin the pin to set
	 */
	public void setPin(char[] pin) {
		this.pin = pin;
	}


	/**
	 * @return the place
	 */
	public FileLocation getPlace() {
		return place;
	}


	/**
	 * @param place the place to set
	 */
	public void setPlace(FileLocation place) {
		this.place = place;
	}


	/* (non-Javadoc)
	 * @see tools.pki.gbay.util.general.FileInterface#getContent()
	 */
	@Override
	public PlainText getContent() {
		return content;
	}


	/**
	 * @param content the content to set
	 */
	public void setContent(PlainText content) {
		this.content = content;
	}


	/* (non-Javadoc)
	 * @see tools.pki.gbay.util.general.FileInterface#getFile()
	 */
	@Override
	public File getFile() {
		return new File(path);
	}


	

	/* (non-Javadoc)
	 * @see tools.pki.gbay.util.general.FileInterface#getPath()
	 */
	@Override
	public String getPath() {
		return path;
	}


	/**
	 * @return the mode
	 */
	public OpenMode getMode() {
		return mode;
	}


	/**
	 * @param mode the mode to set
	 */
	public void setMode(OpenMode mode) {
		this.mode = mode;
	}
	
	
}

