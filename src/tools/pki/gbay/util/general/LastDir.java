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

/**
 *
 * @author Araz
 */
public class LastDir {
    
	/** Last directory. */
	private File m_fLastDir;

	/**
	 * Construct an empty LastDir object.
	 */
	public LastDir()
	{
		// Default last directory to current directory if it exists
		String currentDir = System.getProperty("user.dir");
		if (currentDir != null)
		{
			m_fLastDir = new File(currentDir);
			if (!m_fLastDir.exists())
			{
				m_fLastDir = null;
			}
			else if (!m_fLastDir.isDirectory())
			{
				m_fLastDir = m_fLastDir.getParentFile();
			}
		}
	}

	/**
	 * Construct a LastDir object based on the supplied file.
	 * 
	 * @param file Used to set last directory
	 */
	public LastDir(File file)
	{
		m_fLastDir = new File(file.toString());
	}

	/**
	 * Update the LastDir object based on the supplied file. If the file exists and is a directory it is used,
	 * if it exists and is a regular file then its parent is used.
	 * 
	 * @param file Used to set last directory
	 */
	public void updateLastDir(File file)
	{
		if (file != null && file.exists())
		{
			m_fLastDir = file.isDirectory() ? file : file.getParentFile();
		}
	}

	/**
	 * Get the last updated directory.
	 * 
	 * @return Last directory if the last update still exists, false otherwise
	 */
	public File getLastDir()
	{
		if (m_fLastDir != null && m_fLastDir.exists())
		{
			return new File(m_fLastDir.toString());
		}
		return null;
	}
}
