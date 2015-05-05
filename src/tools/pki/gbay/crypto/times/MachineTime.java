package tools.pki.gbay.crypto.times;

import java.util.Date;

public class MachineTime implements TimeInterface{

	@Override
	public Date GetCurrentTime() {
		
		return new Date();
	}

}
