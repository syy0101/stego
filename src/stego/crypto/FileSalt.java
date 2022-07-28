package stego.crypto;

import java.security.SecureRandom;

public class FileSalt extends GuardedByteArray
{
    public static final int SIZE = 32;
    public FileSalt()
    {
	this(new SecureRandom());
    }
    public FileSalt(SecureRandom random)
    {
	super(new byte[SIZE]);
	random.nextBytes(super.bytes);
    }
    public FileSalt(byte[] source)
    {
	super(source);
	if(source.length != SIZE) {
	    throw new IllegalArgumentException("FileSalt size is not "+source.length);
	}
    }
}
