package tools.pki.gbay.util.general;

import java.io.File;
import java.net.URL;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class RuntimeEnvironment
{
	public static int RETRY_COUNT = 5;
	
	public static boolean isJDK15()
	{
		if(System.getProperty("java.version").trim().startsWith("1.5"))
			return true;
		else
			return false;
	}
	
	public static boolean isJDK14()
	{
		if(System.getProperty("java.version").trim().startsWith("1.4"))
			return true;
		else
			return false;
	}
	
	@SuppressWarnings("rawtypes")
	public static String getVersion(Class loadedClass)
	{
		URL jar = loadedClass.getProtectionDomain().getCodeSource().getLocation();
		try{
			JarFile jf = new JarFile(new File(jar.toURI()));
			Enumeration files = jf.entries();
			jf.close();
			while(files.hasMoreElements())
			{
				JarEntry entry = (JarEntry) files.nextElement();
//				System.out.println("Entry : "+entry.getName());
//				System.out.println("Substring : "+entry.getName().substring(0,3));
				if (entry.getName().trim().substring(0, 3).equals("ver"))
					return entry.getName().trim().substring(4);
			}
			
		}catch (Exception ex)
		{
			return "Unknown version with exception ["+ex.getMessage()+"]";
		}
		
		return "Unknown version";
	}
}


