package jaircrack;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import org.junit.Test;

public class PcapReaderTest {

	@Test
	public void readCap() throws IOException {
		InputStream in = PcapReaderTest.class.getResourceAsStream("simple.cap");
		try {
			PcapReader pcapReader = new PcapReader(in);
			PcapReader.PcapRecord r;
			int recordCount = 0;
			while ((r = pcapReader.readPcapRecord()) != null) {
				System.out.println("Record: " + Arrays.toString(r.data));
				recordCount++;
			}
			
			assertEquals(3, recordCount);
		} finally {
			in.close();
		}
	}
}
