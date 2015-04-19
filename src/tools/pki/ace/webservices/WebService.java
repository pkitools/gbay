package tools.pki.ace.webservices;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class WebService
{
    
    public static void enableSSL()
    {
        try
        {
            SSLContext sc = SSLContext.getInstance("SSL");

            HostnameVerifier hv = new HostnameVerifier()
            {
                public boolean verify(String urlHostName, SSLSession session)
                {
                    return true;
                }
            };
            TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager()
            {
                public java.security.cert.X509Certificate[] getAcceptedIssuers()
                {
                    return null;
                }

                public void checkClientTrusted(
                        java.security.cert.X509Certificate[] certs,
                        String authType)
                {
                }

                public void checkServerTrusted(
                        java.security.cert.X509Certificate[] certs,
                        String authType)
                {
                }
            } };

            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            SSLSocketFactory sslSocketFactory = sc.getSocketFactory();

            HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory);
            HttpsURLConnection.setDefaultHostnameVerifier(hv);

        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }
    
    
}
