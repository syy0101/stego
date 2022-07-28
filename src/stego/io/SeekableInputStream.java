package stego.io;

import java.io.*;
import java.nio.channels.FileChannel;
import java.util.*;
public class SeekableInputStream extends FilterInputStream
{
    private long markPosition = 0;
    public SeekableInputStream(File f)
	throws IOException
    {
	super(new FileInputStream(f));
    }
    public boolean markSupported()
    {
	return true;
	//return super.markSupported();
    }
    private FileChannel getChannel()
    {
	return ((FileInputStream)(super.in)).getChannel();
    }
	
    public void mark(int readLimit)
    {
	try {
	    //super.mark(readLimit);
	    this.markPosition = getChannel().position();
	    //logAndShow(markPosition);
	}
	catch(IOException ioe) {
	    throw new UncheckedIOException(ioe);
	}	    
    }
    private Set<Long> pastResetPositions = Collections.synchronizedSet(new HashSet<Long>());
    private void logAndShow(long n)
    {
	if(pastResetPositions.contains(n)) {
	    return;
	}
	pastResetPositions.add(n);
	new Exception("new reset position:"+n).printStackTrace();
    }
    public void reset()
	throws IOException
    {
	//super.reset();
	getChannel().position(this.markPosition);
    }
    public long skip(long n)
	throws IOException
    {
	long current = getChannel().position();
	getChannel().position(current+n);
	return getChannel().position() - current;
    }
    public void seek(long n)
	throws IOException
    {
	getChannel().position(n);
    }
}
