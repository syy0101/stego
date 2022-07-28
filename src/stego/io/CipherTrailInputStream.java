package stego.io;

import java.io.*;
import java.util.*;
import java.util.stream.*;
import stego.crypto.*;

public class CipherTrailInputStream
    extends FilterInputStream
{
    private long position;
    private final long end;
    private long mark = -1l;
    private final CipherTrail ciphertrail;
    public CipherTrailInputStream(InputStream in, CipherTrail ciphertrail)
    {
	super(in);
	this.ciphertrail = ciphertrail;
	position = 0l;
	end = -1l;
    }
    public CipherTrailInputStream(InputStream in, CipherTrail ciphertrail, long start, long end)
    {
	super(in);
	if(end>=0) {
	    if(start> end) {
		throw new IllegalArgumentException("CipherTrailInputStream start "+start+" > end "+end);
	    }
	}
	this.end = end;
	this.ciphertrail = ciphertrail;
	this.position = start;
	//skip(start);
    }
    public void mark(int readlimit)
    {
	mark = position;
	super.mark(readlimit);
    }
    public void reset()
	throws IOException
    {
	position = mark;
	super.reset();
    }
    public boolean markSupported()
    {
	return super.markSupported();
    }
    public void throwIfOver(long n)
    {
	if(end<0)
	    return;
	if(n>end) {
	    throw new IllegalArgumentException("Trying to seek past end "+end+" to "+n);
	}
    }
    public long skip(long n)
    	throws IOException
    {
	n = super.skip(n);
	position += n;
	throwIfOver(position);
	return n;
    }
    public int read()
	throws IOException
    {
	byte[] b = new byte[1];
	int result = read(b);
	if(result<1) {
	    return -1;
	}
	try {
	    return Byte.toUnsignedInt(b[0]);
	}
	finally {
	    b[0] = (byte)0;
	}
    }
    public int read(byte[] b)
	throws IOException
    {
	return read(b, 0, b.length);
    }
    public int read(byte[] b, int off, int len)
	throws IOException
    {
	//System.out.print("read:"+position+","+len);
	throwIfOver(position+len);
	int result = super.read(b, off, len);
	if(result<1)
	    return result;
	len = result;
	try(GuardedByteArray mask = new GuardedByteArray(ciphertrail.getMask(position,len))) {
	    IntStream.range(0,mask.bytes.length).parallel()
		.forEach(i-> b[i+off] ^= mask.bytes[i]);
	}
	position += len;
	//System.out.println(","+position);
	return len;
    }
}
