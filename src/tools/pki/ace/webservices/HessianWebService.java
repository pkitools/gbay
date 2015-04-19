package tools.pki.ace.webservices;


import com.caucho.hessian.client.HessianProxyFactory;

public abstract class HessianWebService {
	String address;
	boolean isSSL;
	HessianProxyFactory factory = new HessianProxyFactory() ;
//	Object service;
	public HessianWebService(String url, boolean isSSL) {
		if (isSSL)
		WebService.enableSSL();

//		HessianProxyFactory factory = new HessianProxyFactory();
	}
	/**
	 * @return the address
	 */
	public String getAddress() {
		return address;
	}
	/**
	 * @param address the address to set
	 */
	public void setAddress(String address) {
		this.address = address;
	}
	/**
	 * @return the isSSL
	 */
	public boolean isSSL() {
		return isSSL;
	}
	/**
	 * @param isSSL the isSSL to set
	 */
	public void setSSL(boolean isSSL) {
		this.isSSL = isSSL;
	}
	/**
	 * @return the factory
	 */
	public HessianProxyFactory getFactory() {
		return factory;
	}
	/**
	 * @param factory the factory to set
	 */
	public void setFactory(HessianProxyFactory factory) {
		this.factory = factory;
	}

}
