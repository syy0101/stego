package stego.io;

import java.io.*;
import java.util.Arrays;
import java.util.stream.IntStream;
import stego.crypto.*;

public class CipherTrailOutputStream
    extends FilterOutputStream
{
    private long position;
    private final long end;
    private final CipherTrail ciphertrail;
    public CipherTrailOutputStream(OutputStream out, CipherTrail ciphertrail)
    {
	super(out);
	this.ciphertrail = ciphertrail;
	position = 0l;
	end = -1l;
    }
    public CipherTrailOutputStream(OutputStream out, CipherTrail ciphertrail, long start, long end)
	throws IOException
    {
	super(out);
	if(end>=0) {
	    if(start> end) {
		throw new IllegalArgumentException("CipherTrailOutputStream start "+start+" > end "+end);
	    }
	}
	this.ciphertrail = ciphertrail;
	this.position = 0l;
	this.end = end;
	//	seek(start);
    }
    public void throwIfOver(long n)
    {
	if(end<0)
	    return;
	if(n>end) {
	    throw new IllegalArgumentException("Trying to seek past end "+end+" to "+n);
	}
    }
    /*
    public void seek(long n)
	throws IOException
    {
	throwIfOver(n);
	position = n;
	((FileOutputStream)(super.out)).getChannel().position(n);
    }
    */
    public void write(int by)
	throws IOException
    {
	byte[] b = new byte[1];
	try {
	    b[0] = (byte)by;
	    write(b);
	}
	finally {
	    b[0] = (byte)0;
	}
    }
    public void write(byte[] b)
	throws IOException
    {
	write(b, 0, b.length);
    }
    public void write(byte[] b, int off, int len)
	throws IOException
    {
	if((off<0)||(len<0)||(off>=b.length)) {
	    throw new IllegalArgumentException("("+off+"<0)||("+len+"<0)||("+off+">="+b.length+")");
	}
	throwIfOver(position+len);
	try(GuardedByteArray mask = new GuardedByteArray(ciphertrail.getMask(position,len))) {
	    IntStream.range(0,mask.bytes.length).parallel()
		.forEach(i-> mask.bytes[i] ^= b[i+off]);
	    super.out.write(mask.bytes);
	    position += len;
	}
    }
}
