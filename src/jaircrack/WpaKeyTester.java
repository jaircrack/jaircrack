package jaircrack;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;


public class WpaKeyTester {

	final Mac sha1Mac;
	final Mac mac;

	final byte[] pke = new byte[100];

	final ApInfo apInfo;

	public WpaKeyTester(ApInfo apInfo) {

		/**** Set up the Macs we're going to need ****/
		try {
			sha1Mac = Mac.getInstance("HmacSHA1");

			if (apInfo.wpa.keyver == 1) {
				mac = Mac.getInstance("HmacMD5");
			} else {
				mac = Mac.getInstance("HmacSHA1");
			}
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}

		/**** Set up PKE ****/
		ByteBuffer pkeBuffer = ByteBuffer.wrap(pke);

		// 23 total
		try {
			pkeBuffer.put("Pairwise key expansion\0".getBytes("ASCII"));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("ASCII not supported.", e);
		}

		// 12 total
		if (memcmp(apInfo.wpa.stmac, apInfo.bssid, 6) < 0) {
			pkeBuffer.put(apInfo.wpa.stmac);
			pkeBuffer.put(apInfo.bssid);
		} else {
			pkeBuffer.put(apInfo.bssid);
			pkeBuffer.put(apInfo.wpa.stmac);
		}

		// 64 total
		if (memcmp(apInfo.wpa.snonce, apInfo.wpa.anonce, 32) < 0) {
			pkeBuffer.put(apInfo.wpa.snonce);
			pkeBuffer.put(apInfo.wpa.anonce);
		} else {
			pkeBuffer.put(apInfo.wpa.anonce);
			pkeBuffer.put(apInfo.wpa.snonce);
		}

		this.apInfo = apInfo;
	}

	protected boolean testKey(byte[] key) {
		try {
			SecretKeySpec pmk = new SecretKeySpec(this.calc_pmk(key), 0, 32, "HmacSHA1");
			sha1Mac.init(pmk);
		} catch (InvalidKeyException e) {
			throw new RuntimeException();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException();
		}

		byte[] ptk = new byte[80];

		for (int i = 0; i < 4; i++) {
			pke[99] = (byte)i;
			sha1Mac.update(pke);
			try {
				sha1Mac.doFinal(ptk, i * 20);
			} catch (ShortBufferException e) {
				throw new RuntimeException();
			}
		}

		try {
			if (apInfo.wpa.keyver == 1) {
				this.mac.init(new SecretKeySpec(ptk, 0, 16, "HmacMD5"));
			} else {
				this.mac.init(new SecretKeySpec(ptk, 0, 16, "HmacSHA1"));
			}
		} catch (InvalidKeyException e) {
			throw new RuntimeException(e);
		}

		this.mac.update(this.apInfo.wpa.eapol);
		byte[] result = this.mac.doFinal();

		return memcmp(result, this.apInfo.wpa.keymic, 16) == 0;
	}

	public byte[] calc_pmk(byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
		try {
			MessageDigest ipad = MessageDigest.getInstance("SHA-1");
			MessageDigest opad = MessageDigest.getInstance("SHA-1");

			int keyCutoff = Math.min(key.length, 64);

			for (int i = 0; i < keyCutoff; i++) {
				ipad.update((byte)(key[i] ^ 0x36));
				opad.update((byte)(key[i] ^ 0x5c));
			}
			for (int i = keyCutoff; i < 64; i++) {
				ipad.update((byte)0x36);
				opad.update((byte)0x5c);
			}

			byte[] pmk = new byte[40];

			sha1Mac.init(new SecretKeySpec(key, "HmacSHA1"));

			byte[] essid = Arrays.copyOf(this.apInfo.essid, this.apInfo.essid.length + 4);

			essid[essid.length - 1] = 1;
			sha1Mac.update(essid);
			sha1Mac.doFinal(pmk, 0);

			byte[] buffer = Arrays.copyOf(pmk, 20);

			// TODO: replace with PBKDF2?
			for (int i = 4094; i >= 0; i--) {
				MessageDigest temp;

				temp = (MessageDigest)ipad.clone();
				temp.update(buffer);
				temp.digest(buffer, 0, buffer.length);

				temp = (MessageDigest)opad.clone();
				temp.update(buffer);
				temp.digest(buffer, 0, buffer.length);

				for (int j = buffer.length - 1; j >= 0; j--) {
					pmk[j] ^= buffer[j];
				}
			}


			essid[essid.length - 1] = 2;
			sha1Mac.update(essid);
			sha1Mac.doFinal(pmk, 20);
			buffer = Arrays.copyOfRange(pmk, 20, 40);

			// TODO: replace with PBKDF2?
			for (int i = 4094; i >= 0; i--) {
				MessageDigest temp;

				temp = (MessageDigest)ipad.clone();
				temp.update(buffer);
				temp.digest(buffer, 0, buffer.length);

				temp = (MessageDigest)opad.clone();
				temp.update(buffer);
				temp.digest(buffer, 0, buffer.length);

				for (int j = buffer.length - 1; j >= 0; j--) {
					pmk[j + 20] ^= buffer[j];
				}
			}


			return pmk;
		} catch (ShortBufferException e) {
			throw new RuntimeException();
		} catch (CloneNotSupportedException e) {
			// FIXME:
			throw new RuntimeException();
		} catch (DigestException e) {
			// TODO Auto-generated catch block
			throw new RuntimeException();
		}
	}

	protected static int memcmp(byte[] a, byte[] b, int maxLen) {
		for (int i = 0; i < maxLen; i++) {
			int diff = (a[i] & 0xff) - (b[i] & 0xff);
			if (diff != 0) {
				return diff;
			}
		}
		return 0;
	}
}
