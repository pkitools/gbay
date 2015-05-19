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

package tools.pki.gbay.errors;

import org.apache.log4j.Logger;

/**
 *
 * @author Araz
 */
public class CryptoException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private int errorCode;
	private String title;
	private String errorName;
	private String message;
	private String description;
	Logger log = Logger.getLogger(CryptoException.class);

	public enum LogLevel {
		ERROR, WARNING, INFO, DEBUG;
	}

	public CryptoException(CryptoError accourdError) {
		super("Error number " + accourdError.getError().id + " Happened, "
				+ accourdError.getMessage(), new Throwable(
				accourdError.getDescription()));
		readError(accourdError);
	}

	public CryptoException(GlobalErrorCode accourdError) {
		this(new CryptoError(accourdError));
	}

	public CryptoException(CryptoError accourdError, Exception e) {
		super(e);
		readError(accourdError);
	}

	public CryptoException(CryptoError accourdError, Class<?> callerClass,
			LogLevel level, boolean exception) throws CryptoException {
		this(accourdError);

	}

	public CryptoException(String errorText) {
		super(errorText, new Throwable(errorText));
		this.message = errorText;
		this.title = errorText;
		this.description = errorText;
	}

	public CryptoException(int err) {
		this(new CryptoError(err));

	}

	public CryptoException(Exception e) {
		super(e);
		if (e instanceof CryptoException) {
			copy((CryptoException) e, this);
		}
		this.message = e.getMessage();
		if (e.getCause() != null)
			this.title = e.getCause().getMessage();
		else
			this.title = "Error";
	}

	public CryptoException(GlobalErrorCode certInvalidFormat, String message2) {
	this (new CryptoException(certInvalidFormat,message2));
	}

	private void readError(CryptoError accourdError) {
		log.debug("Reading error " + accourdError.getError().name());
		this.errorCode = accourdError.getErrorCode();
		log.debug("Error number: " + errorCode);
		this.message = accourdError.getMessage();
		this.title = accourdError.getTitle();
		this.errorName = accourdError.getError().name();
		this.description = accourdError.getDescription();

	}

	public int getErrorCode() {
		return errorCode;
	}

	/**
	 * @param error
	 *            the error to set
	 */
	public void setError(CryptoError error) {
		readError(error);
	}

	/**
	 * @return the title
	 */
	public String getTitle() {
		return title;
	}

	/**
	 * @return the errorName
	 */
	public String getErrorName() {
		return errorName;
	}

	/**
	 * @return the message
	 */
	public String getMessage() {
		return message;
	}

	/**
	 * @return the description
	 */
	public String getDescription() {
		return description;
	}

	@Override
	protected CryptoException clone() throws CloneNotSupportedException {
		CryptoException copy = new CryptoException(this);
		copy(this, copy);
		return copy;

	}

	protected void copy(CryptoException source, CryptoException destination) {
		destination.errorCode = source.errorCode;
		destination.title = source.title;
		destination.errorName = source.errorName;
		destination.message = source.message;
		destination.description = source.description;
	}
}
