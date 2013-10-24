package jaircrack;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;


public class PcapReader {
	public static final int MAGIC = 0xa1b2c3d4;
	
	protected static final byte[] DISCARD_BUFFER = new byte[2048];
	
	protected final InputStream in;
	
	protected final int maxRecordSize = 1024 * 1024 * 16;
	protected final ByteOrder order;
	
	
	// major version number
	protected final int versionMajor;
	
	// minor version number
	protected final int versionMinor;
	
	// GMT to local correction
	protected final int thisZone;
	
	// accuracy of timestamps
	protected final long sigfigs;
	
	// max length of captured packets, in octets
	protected final long snaplen;
	
	// data link type
	protected final long network;
	
	public PcapReader(InputStream in) throws PcapException, IOException {
		
		this.in = in;
		
		ByteBuffer header = ByteBuffer.allocate(24);
		
		int read;
		while (header.hasRemaining() && (read = in.read(header.array(), header.arrayOffset() + header.position(), header.remaining())) >= 0) {
			header.position(header.position() + read);
		}
		if (header.hasRemaining()) {
			throw new PcapException("Incomplete header");
		}
		
		header.flip();
		
		ByteOrder order = ByteOrder.BIG_ENDIAN;
		orderBlock: {
			header.order(order);
			header.mark();
			if (header.getInt() == MAGIC) {
				break orderBlock;
			}
			
			order = ByteOrder.LITTLE_ENDIAN;
			header.order(order);
			header.reset();
			if (header.getInt() == MAGIC) {
				break orderBlock;
			}
			
			throw new PcapException("Stream doesn't appear to be a PCAP stream");
		}
		
		this.order = order;
		
		// major version number
		versionMajor = header.getShort() & 0xffff;
		
		// minor version number
		versionMinor = header.getShort() & 0xffff;
		
		// GMT to local correction
		thisZone = header.getInt();
		
		// accuracy of timestamps
		sigfigs = header.getInt() & 0xffffffffl;
		
		// max length of captured packets, in octets
		snaplen = header.getInt() & 0xffffffffl;
		
		// data link type
		network = header.getInt() & 0xffffffffl;	
	}
	
	public PcapRecord readPcapRecord() throws IOException, PcapException {
		while (true) {
			ByteBuffer header = ByteBuffer.allocate(16);
			header.order(this.order);
			
			int read;
			while (header.hasRemaining() && (read = in.read(header.array(), header.arrayOffset() + header.position(), header.remaining())) >= 0) {
				header.position(header.position() + read);
			}
			if (header.hasRemaining()) {
				return null;
			}
			
			header.flip();
			
			long ts_sec = header.getInt() & 0xffffffffl;
			long ts_usec = header.getInt() & 0xffffffffl;
			
			long includedLength = header.getInt() & 0xffffffffl;
			long originalLength = header.getInt() & 0xffffffffl;
		
			if (includedLength > this.snaplen) {
				throw new PcapException(String.format("includedLength %d is greater than max snaplen %d; The stream is likely corrupt.", includedLength, this.snaplen));
			}
			if (includedLength > this.maxRecordSize) {
				while ((in.read(DISCARD_BUFFER)) >= 0);
			} else {
				byte[] data = new byte[(int)includedLength];
				ByteBuffer recordBuffer = ByteBuffer.wrap(data);
				while (recordBuffer.hasRemaining() && (read = in.read(recordBuffer.array(), recordBuffer.arrayOffset() + recordBuffer.position(), recordBuffer.remaining())) >= 0) {
					recordBuffer.position(recordBuffer.position() + read);
				}
				if (recordBuffer.hasRemaining()) {
					return null;
				}
				
				return new PcapRecord(data, originalLength);
			}
		}
	}
	
	public static class PcapRecord {
		final byte[] data;
		final long originalLength;
		
		protected PcapRecord(byte[] data, long originalLength) {
			if (data == null) {
				throw new NullPointerException("data was null");
			}
			if (originalLength < 0 || originalLength < data.length) {
				throw new IllegalArgumentException("Bad originalLength");
			}
			this.data = data;
			this.originalLength = originalLength;
		}
	}
	
	public static class PcapException extends IOException {

		private static final long serialVersionUID = -49291216766037351L;

		public PcapException(String message) {
			super(message);
		}

	}
}
