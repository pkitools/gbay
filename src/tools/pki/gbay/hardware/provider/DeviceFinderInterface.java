package tools.pki.gbay.hardware.provider;

import java.util.List;

import tools.pki.gbay.hardware.pcsc.CardInfo;

public interface DeviceFinderInterface {

	int selectCard(List<CardInfo> conectedCardsList);

}
