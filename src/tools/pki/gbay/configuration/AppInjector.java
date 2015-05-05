package tools.pki.gbay.configuration;

import tools.pki.gbay.crypto.provider.SignatureSettingInterface;
import tools.pki.gbay.crypto.provider.SignatureTime;

import com.google.inject.AbstractModule;
import com.google.inject.Singleton;

public class AppInjector extends AbstractModule {

	@Override
	protected void configure() {
			
        bind(SignatureSettingInterface.class).to(DefualtSignatureSetting.class).in(Singleton.class);
	}

}
