package jaircrack;
import java.util.Arrays;


public class WifiParser {

	public void test(byte[] packet) {

		/* skip packets smaller than a 802.11 header */
		if (packet.length < 24 ) {
			return;
		}

		/* skip (uninteresting) control frames */
		if(( packet[0] & 0x0C) == 0x04) {
			return;
		}

		/* locate the access point's MAC address */
		byte[] bssid;
		byte[] dest;

		switch (packet[1] & 3) {
			case 0: bssid = Arrays.copyOfRange(packet, 16, 22); break;  //Adhoc
			case 1: bssid = Arrays.copyOfRange(packet, 4, 10);  break;  //ToDS
			case 2: bssid = Arrays.copyOfRange(packet, 10, 16); break;  //FromDS
			case 3: bssid = Arrays.copyOfRange(packet, 10, 16); break;  //WDS -> Transmitter taken as BSSID
		}

		switch (packet[1] & 3) {
			case 0: dest = Arrays.copyOfRange(packet, 4, 10); break;   //Adhoc
			case 1: dest = Arrays.copyOfRange(packet, 16, 22); break;  //ToDS
			case 2: dest = Arrays.copyOfRange(packet, 4, 10); break;   //FromDS
			case 3: dest = Arrays.copyOfRange(packet, 16, 22); break;  //WDS -> Transmitter taken as BSSID
		}
		
		// TODO:

	}
}
