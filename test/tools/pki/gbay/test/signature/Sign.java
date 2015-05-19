package tools.pki.gbay.test.signature;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import org.apache.commons.io.IOUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import tools.pki.gbay.configuration.AppInjector;
import tools.pki.gbay.configuration.PropertyFileConfiguration;
import tools.pki.gbay.crypto.GbayApi;
import tools.pki.gbay.crypto.provider.SignatureSettingInterface;
import tools.pki.gbay.crypto.texts.SignedText;
import tools.pki.gbay.crypto.texts.VerifiedText;
import tools.pki.gbay.errors.CryptoException;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Singleton;

public class Sign {

	private Injector injector;

	@Before
	public void setUp() throws Exception {
		injector = Guice.createInjector(new AbstractModule() {

			@Override
			protected void configure() {
//			    bind(SignatureSettingInterface.class).to(PropertyFileConfiguration.class).in(Singleton.class);

//				bind(SignatureSettingInterface.class).to(
	//					DefualtSignatureSetting.class);
			}

			// @Override
			// protected void configure() {
			// bind(S.class).to(MockMessageService.class);
			// }
		});
	}

	@After
	public void tearDown() throws Exception {
		injector = null;
	}

	@Test
	public void test() throws IOException, CryptoException, CertificateEncodingException, NoSuchAlgorithmException {
		InputStream fl = new FileInputStream("testcerts/certificate.pfx");
	    Injector injector = Guice.createInjector(new AppInjector());
	    
	    
		GbayApi appTest = injector.getInstance(GbayApi.class);
		SignedText st = appTest.sign(IOUtils.toByteArray(fl), "zaq12wsx", "hi");

		System.err.println(st.toBase64());
	//	X509Certificate certificates = null;
	//	CertificateIssuer ci = new CertificateIssuer("mycert",certificates);
	try{
		System.err.println(st.getSignedVal());
		VerifiedText vt = appTest.verify("hi", st.getSignedVal());
		System.out.println(vt.isPassed());
		
	}
	catch (CryptoException err){
	
	}
		// Assert.assertEquals(true, appTest.signAttach(pfx, pin,
		// messageToSign)("Hi Pankaj", "pankaj@abc.com"));;
	}
}
