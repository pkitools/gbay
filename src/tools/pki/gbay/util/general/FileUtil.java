package tools.pki.gbay.util.general;

import java.awt.List;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.channels.FileChannel;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import tools.pki.gbay.util.general.FileUtil;

public class FileUtil {

	public static String getFileType(String fileName) {

		String type = "text";

		if ((fileName.endsWith(".png")) || (fileName.endsWith(".gif"))
				|| (fileName.endsWith(".jpg"))) {
			type = "binary";
		} else if ((fileName.endsWith(".html")) || (fileName.endsWith(".css"))
				|| (fileName.endsWith(".js"))) {
			type = "text";
		}

		return type;

	}

	/*
	 * Read a certificate from the specified filepath.
	 */	
	public static X509Certificate getCertFromFile(File path) throws CertificateException, FileNotFoundException {
		return GetCert(new FileInputStream(path));
	}
	
	public static X509Certificate GetCert(InputStream is) throws CertificateException{
		X509Certificate cert = null;
		CertificateFactory cf = CertificateFactory.getInstance("X509");
	
		cert = (X509Certificate) cf.generateCertificate(is);
	return cert;
	}

	
	public static String loadText(String resource) {

		StringBuffer strBuffer = new StringBuffer();

		InputStream is = null;
		BufferedReader br = null;
		String line;

		try {
			is = FileUtil.class.getResourceAsStream(resource);
			if (is == null)
				throw new Exception("Resource " + resource + " was not found.");
			br = new BufferedReader(new InputStreamReader(is));
			while (null != (line = br.readLine())) {
				strBuffer.append(line + '\n');
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (br != null)
					br.close();
				if (is != null)
					is.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return strBuffer.toString();
	}

	public static byte[] loadBinary(String resource) {
		byte[] buffer = new byte[1024];
		InputStream is = null;
		BufferedReader br = null;
		ByteArrayOutputStream baos = null;

		try {
			is = FileUtil.class.getResourceAsStream(resource);
			if (is == null)
				throw new Exception("Resource " + resource + " was not found.");
			br = new BufferedReader(new InputStreamReader(is));
			int bytesRead;

			baos = new ByteArrayOutputStream();

			while ((bytesRead = is.read(buffer)) != -1) {
				baos.write(buffer, 0, bytesRead);
			}

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (br != null)
					br.close();
				if (is != null)
					is.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return baos.toByteArray();
	}

	public static byte[] getDataFromFile(String fileName) throws IOException {
		System.out.println("file:" +fileName);
		int i, len;
		byte[] data = null;
		FileInputStream fp = null;

		fp = new FileInputStream(fileName);
		len = fp.available();
		data = new byte[len];
		i = 0;
		while (i < len) {
			i += fp.read(data, i, len - i);
		}
		fp.close();
		return data;
	}

	public static List listCerts(String path) {
		String files = new String();
		List result = new List();
		File folder = new File(path);
		File[] listOfFiles = folder.listFiles();

		for (int i = 0; i < listOfFiles.length; i++) {
			if (listOfFiles[i].isFile()) {
				files = listOfFiles[i].getName();
				if (files.endsWith(".cer") || files.endsWith(".CER")) {
					result.add(files);
				}
			}
		}
		return result;
	}

	public static void copyFile(File sourceFile, File destFile)
			throws IOException {
		if (!destFile.exists()) {
			destFile.createNewFile();
		}

		FileChannel source = null;
		FileChannel destination = null;
		try {
			source = new FileInputStream(sourceFile).getChannel();
			destination = new FileOutputStream(destFile).getChannel();
			destination.transferFrom(source, 0, source.size());
		} finally {
			if (source != null) {
				source.close();
			}
			if (destination != null) {
				destination.close();
			}
		}
	}
}
