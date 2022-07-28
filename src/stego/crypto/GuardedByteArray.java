package stego.crypto;

import java.util.Arrays;
import java.security.SecureRandom;

public class GuardedByteArray
    implements AutoCloseable
{
    public byte[] bytes;
    public GuardedByteArray(byte[] source)
    {
	this.bytes = source;
    }
    public GuardedByteArray(SecureRandom random, int size)
    {
	this.bytes = new byte[size];
	random.nextBytes(this.bytes);
    }
    public void close()
    {
	Arrays.fill(bytes,(byte)0);
	bytes = null;
    }
    public GuardedByteArray append(byte[] afterBytes, boolean clearAfterUse)
    {
	byte[] result = new byte[this.bytes.length + afterBytes.length];
	try {
	    System.arraycopy(bytes,0, result,0, bytes.length);
	    System.arraycopy(afterBytes,0, result,bytes.length, afterBytes.length);
	}
	finally {
	    if(clearAfterUse) {
		Arrays.fill(afterBytes, (byte)0);
	    }
	}
	return new GuardedByteArray(result);
    }
}
