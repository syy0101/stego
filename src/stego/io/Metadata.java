package stego.io;

import java.io.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.IntStream;
import java.nio.*;
import stego.ecc.*;
import stego.crypto.*;
import stego.util.CommandLineInterface;

public class Metadata extends GuardedByteArray
{
    public static final byte RUNWAY_MARKER = (byte)255; // Nothing in my sleeve -constant, but should not be 0 because java new array is filled with 0
    public enum Field
    {
	RUNWAY(8), // all bits here are 1
	KEY(32), // CipherTrail key
	LENGTH(Long.BYTES); // CipherTrail length
	public int start() {
	    int start = 0;
	    for(Field f : values()) {
		if(f.equals(this)) {
		    break;
		}
		start += f.length;
	    }
	    return start;
	}
		
	public final int length;
	public int length() {
	    return length;
	}
	public int end()
	{
	    return start()+length;
	}

	public static int size()
	{
	    int size = 0;
	    for(Field f : values()) {
		size += f.length;
	    }
	    return size;
	}
	//	private static int totalSize = 0;
	private Field(int length)
	{
	    //	    this.start = totalSize;
	    this.length = length;
	    //totalSize += length;
	    //this.end = totalSize;
	}
    }
    public static ArmorCoder getMetadataArmorChain()
    {
	ArmorCoder result =
	    new ReedSolomonCoder(Field.size())
	    .setNext(new HammingCoder());
	return result;
    }

    /**
     * Internal contents are stored in basedata, which is cleared in close().
     **/
    private final byte[] basedata = super.bytes;
    public long getLength()
    {
	return
	    ByteBuffer.wrap(basedata).getLong(Field.LENGTH.start());
    }
    /**
     * @returns copy of key material in a new byte[]. Receiver is responsible of clearing the received buffer after use.
     **/
    public byte[] getKeyCopy()
    {
	byte[] result = new byte[Field.KEY.length];
	System.arraycopy(basedata, Field.KEY.start(), result, 0, Field.KEY.length);
	return result;
    }
    public GuardedByteArray getKey()
    {
	return new GuardedByteArray(getKeyCopy());
    }
    /**
     * @returns a copy of the internal packet. Caller is responsible for clearing the received array.
     **/
    public byte[] getByteCopy()
    {
	byte[] result = basedata.clone();
	return result;
    }
    /**
     * @returns true if RUNWAY is filled with RUNWAY_MARKER
     **/
    public boolean isValid()
    {
	boolean result = true;
	for(int i= Field.RUNWAY.start(); i< Field.RUNWAY.end(); i++) {
	    result = result && (RUNWAY_MARKER == basedata[i]);
	}
	return result;
    }
    /*
    public void close()
    {
	Arrays.fill(basedata,(byte)0);
    }
    */
    /**
     * @param keyMaterial to make a copy to internal contents. Source is not used after constructor, and internal storage is cleared in close()
     * @param length the length of the target data this Metadata points to
     **/
    public Metadata(byte[] keyMaterial, long length)
    {
	super(new byte[Field.size()]);
	if(keyMaterial.length != Field.KEY.length) {
	    throw new IllegalArgumentException("Metadata key size is incorrect, was "+keyMaterial.length+" instead of "+Field.KEY.length);
	}
	ByteBuffer baseBuffer = ByteBuffer.wrap(basedata);
	for(int i = 0; i < Field.RUNWAY.length; i++) {
	    baseBuffer.put(RUNWAY_MARKER);
	}
	baseBuffer.put(keyMaterial);
	baseBuffer.putLong(length);
    }
    /*
    public void setLength(long newLength)
    {
	ByteBuffer.wrap(basedata).putLong(Field.LENGTH.start(),newLength);
    }
    */
    public static Metadata createMetadata(SecureRandom random, long length)
    {
	byte[] key = new byte[Field.KEY.length];
	try {
	    random.nextBytes(key);
	    Metadata result = new Metadata(key, length);
	    return result;
	}
	finally {
	    Arrays.fill(key, (byte)0);
	}
    }	
    public Metadata(byte[] copySource)
    {
	super(copySource);
	if(copySource.length != Field.size()) {
	    throw new IllegalArgumentException("Metadata total size is incorrect, was "+copySource.length+ "instead of "+Field.size());
	}
	//ByteBuffer.wrap(basedata).put(copySource);
    }
    public static Metadata read(InputStream in)
	throws IOException
    {
	byte[] data = new byte[Field.size()];
	int result = in.read(data);
	if(result<data.length) {
	    throw new EOFException("too few bytes of metadata: "+result);
	}
	return new Metadata(data);
    }
    public Metadata cipher(FileSalt filesalt, char[] passcode, byte[] nonce)
    {
	CipherTrail ct = new CipherTrail(filesalt, passcode, nonce);
	Metadata result = new Metadata(super.bytes.clone());
	try(GuardedByteArray mask = new GuardedByteArray(ct.getMask(0,basedata.length))) {
	    IntStream.range(0,basedata.length).parallel()
		.forEach(i -> result.basedata[i] = (byte)(result.basedata[i] ^ mask.bytes[i]));
	    return result;
	}
    }
    public Metadata open(FileSalt filesalt, char[] passcode, SecureRandom random)
    {
	int nonceLength = 0;
	while(true) {
	    try(Nonce nonce = new Nonce(new byte[nonceLength])) {
		random.nextBytes(nonce.bytes);
		try(GuardedByteArray currentZero = new GuardedByteArray(nonce.bytes.clone())) {
		    boolean currentNotCarried = true;
		    while(currentNotCarried) {
			CommandLineInterface.showProgress();
			Metadata decrypted = this.cipher(filesalt,passcode,nonce.bytes);
			if(decrypted.isValid()) {
			    return decrypted;
			} else {
			    currentNotCarried = nonce.incrementAndCheck(currentZero);
			    if(!currentNotCarried) {
			    }
			}
		    }
		    nonceLength++;
		}
	    }
	}
    }
	
}
