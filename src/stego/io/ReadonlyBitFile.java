package stego.io;

import java.io.*;
import java.util.*;
import java.util.function.*;
import java.util.stream.IntStream;
import java.security.SecureRandom;
import stego.crypto.FileSalt;
import stego.crypto.GuardedByteArray;
import stego.crypto.CipherTrail;
import stego.util.CommandLineInterface;
/**
 * @author syy 2022-06-25
 *
 * Class to read and write parallel into a File.
 **/


public class ReadonlyBitFile implements LargeBitfield, AutoCloseable, Supplier<InputStream>
{
    public final byte LOW_BIT_MASK = (byte)0x7;
    
    //private final File targetFile;
    private final Supplier<InputStream> inputStreamSupplier;
    private ThreadLocal<InputStream> threadLocalInputStream
	= new ThreadLocal<InputStream>().withInitial(this);
    private Set<InputStream> openInputStreams = Collections.synchronizedSet(new HashSet<InputStream>());
    private boolean isClosed = false;

    public final long dataLength;
    //    public static final int TAIL_SALT_LENGTH = CipherTrail.FILESALT_SIZE;
    private final FileSalt filesalt;
    //    private final long fileLength;
    //private LockMap<Long> byteLockMap = new LockMap<Long>();

    /**
     * Checks if this RandomAccessBitFile is closed and throws IOException if it is
     *
     * @throws IOException if this file is already closed.
     **/
    private void throwIfClosed()
	throws IOException
    {
	if(isClosed) {
	    throw new IOException("Access to RandomAccessFile after it is closed.");
	}
    }

    /**
     * Opens a new RandomAccessFile to the target File for a Thread to read and write on and attaches it to list of open files to be automatically closed on close().
     *
     * @returns the new RandomAccessFile or null if this RandomAccessBitFile has already been closed.
     **/
    public synchronized InputStream get()
    {
	if(isClosed) return null;
	InputStream in = inputStreamSupplier.get();
	in.mark(0);
	openInputStreams.add(in);
	return in;
    }

    public static class FileSaltSkipper implements Supplier<InputStream>
    {
	private final Supplier<InputStream> upstream;
	public FileSaltSkipper(Supplier<InputStream> upstream)
	{
	    this.upstream = upstream;
	}
	public InputStream get()
	{
	    try {
		InputStream current = upstream.get();
		current.skip(FileSalt.SIZE);
		current.mark(0);
		return current;
	    }
	    catch(IOException ioe) {
		throw new UncheckedIOException(ioe);
	    }
	}
    }

    public static ReadonlyBitFile read(File file, char[] passcode, SecureRandom random)
	throws IOException
    {
	try(FileInputStream fis = new FileInputStream(file)) {
	    try(Metadata metadata = Metadata.read(fis)) {
		ReadonlyBitFile outerFile
		    = new ReadonlyBitFile(file.length()-Metadata.Field.size(), () -> {
			    try {
				SeekableInputStream result = new SeekableInputStream(file);
				result.skip(Metadata.Field.size());
				result.mark(0);
				return result;
			    }
			    catch(IOException ioe) {
				throw new UncheckedIOException(ioe);
			    }
			});
		FileSalt filesalt = outerFile.getFileSalt();
		ReadonlyBitFile result = outerFile.openInnerReadonlyBitFile(metadata.open(filesalt, passcode, random));
		return result;
	    }
	}
    }

    public static ReadonlyBitFile read(File file, Metadata opener)
	throws IOException
    {
	try(FileInputStream fis = new FileInputStream(file)) {
	    try(Metadata metadata = Metadata.read(fis)) {
		ReadonlyBitFile outerFile
		    = new ReadonlyBitFile(file.length()-Metadata.Field.size(), () -> {
			    try {
				InputStream result = new FileInputStream(file);
				result.skip(Metadata.Field.size());
				result.mark(0);
				return result;
			    }
			    catch(IOException ioe) {
				throw new UncheckedIOException(ioe);
			    }
			});
		return outerFile.openInnerReadonlyBitFile(opener);
	    }
	}
    }

    /**
     * Constructs a new RandomAccessBitFile to read and write parallel on target File.
     *
     * @returns new RandomAccessBitFile
     **/
    public ReadonlyBitFile(long length, Supplier<InputStream> initialInputStreamSupplier)
	throws IOException
    {
	this.inputStreamSupplier = new FileSaltSkipper(initialInputStreamSupplier);
	//this.targetFile = raf;
	this.dataLength = length-FileSalt.SIZE;
	//this.threadLocalInputStream = ThreadLocal.withInitial(this.inputStreamSupplier);
	try(InputStream in = initialInputStreamSupplier.get()) {
	    this.filesalt = new FileSalt(getFileSalt(in, length));
	}
    }

    public ReadonlyBitFile openInnerReadonlyBitFile(Metadata opener)
	throws IOException
    {
	return new ReadonlyBitFile(this.dataLength,
				   () -> {
				       try(GuardedByteArray guard = opener.getKey()) {
					   InputStream is =this.inputStreamSupplier.get();
					   //					   is.skip(FileSalt.SIZE);
					   is.mark(0);
					   return new CipherTrailInputStream(is,
									     new CipherTrail(this.filesalt, guard.bytes)//,
									     //0l, this.dataLength
									     );
				       }
				       //catch(IOException ioe) {
				       //   throw new UncheckedIOException(ioe);
				       //}
	});
    }

    public FileSalt getFileSalt()
    {
	return this.filesalt;
    }
    private static byte[] getFileSalt(InputStream in, long length)
	throws IOException
    {
	//in.mark(0);
	//in.skip(length-TAIL_SALT_LENGTH);
	byte[] result = new byte[FileSalt.SIZE];
	in.read(result);
	//in.reset();
	return result;
    }
    /*
    public static void createNewBitFile(File raf, long size)
	throws IOException
    {
	createNewBitFile(raf, size, new SecureRandom());
    }
    
    public static void createNewBitFile(File raf, long size, SecureRandom random)
	throws IOException
    {
	final int BUFSIZE = 1024*1024;
	byte[] randbuf = new byte[BUFSIZE];
	try(FileOutputStream fos = new FileOutputStream(raf)) {
	    while(size > 0) {
		random.nextBytes(randbuf);
		fos.write(randbuf, 0, Math.toIntExact(Math.min(BUFSIZE, size)));
		size -= BUFSIZE;
	    }
	}
	finally {
	    Arrays.fill(randbuf, (byte)0);
	}
    }
    */
    /**
     * Closes this RandomAccessBitFile and all of its RandomAccessFiles that are used to read and write the target File.
     *
     * @throws IOException if closing one of the RandomAccessFiles throws IOException.
     **/
    public synchronized void close()
	throws IOException
    {
	if(isClosed) return;
	isClosed = true;
	Optional<Exception> oe =
	    openInputStreams.stream()
	    .map(f -> {
		    try {
			f.close();
		    }
		    catch(Exception e) {
			return e;
		    }
		    return null;
		})
	    .filter(e -> null != e)
	    .findAny();
	if(oe.isPresent()) {
	    throw new IOException(oe.get());
	}
	openInputStreams.clear();
    }
    
    /**
     * Reads a bit in the address modulo size bits. 
     *
     * @param address target address
     * @return state of bit in address
     **/
    /*
    public boolean getBit(long address)
	throws IOException
    {
	long byteAddress = Math.floorMod((address / 8), dataLength);
	//	try(LockMap.Lock myLock = byteLockMap.lock(byteAddress)) {
	//	InputStream in = threadLocalInputStream.get();
	byte bitAddress = (byte)(LOW_BIT_MASK & address);
	byte bitMask = (byte)(1 << bitAddress);
	InputStream in = threadLocalInputStream.get();
	in.reset();
	in.skip(byteAddress);
	int res = in.read();
	if(res<0) {
	    throw new EOFException("can't find address "+address+" res:"+res);
	}
	byte source = (byte)res;
	boolean result = (0 != (source & bitMask));
	in.reset();
	return result;
	    //	}
	    //}
    }
    */
    public boolean getBit(long address)
	throws IOException
    {
	long relativeAddress = getRelative(address);
	//int position = Math.toIntExact(relativeAddress - windowStart);
	int bitPosition = Math.toIntExact(relativeAddress & 0x7);
	long bytePosition
	    = relativeAddress >> 3;
	    //= position >> 3;
	byte bitMask = (byte)(1<<bitPosition);
	InputStream in = threadLocalInputStream.get();
	in.reset();
	in.skip(bytePosition);
	int res = in.read();
	if(res<0) {
	    throw new EOFException("can't find address "+address+" res:"+res);
	}
	byte source = (byte)res;
	boolean result = (0 != (source & bitMask));
	in.reset();
	return result;
    }

    /**
     * Makes the target address relative to the data area of which this slice is a slice of.
     *
     * @return relative address, which may be outside this slice.
     **/
    private long getRelative(long address)
    {
	long relativeAddress = Math.floorMod(address, dataLength);
	return relativeAddress;
    }

    /**
     * Checks if the target address is within this slice.
     *
     * @return if the target address is within this slice.
     **/
    /*
    public boolean hasBit(long address)
    {
	long relativeAddress = getRelative(address);
	if(relativeAddress < windowStart)
	    return false;
	if(relativeAddress < windowEnd)
	    return true;
	return false;
    }
    */
    /**
     * Writes a bit into target address.
     * If the address ends outside this slice, it is ignored.
     *
     * @param address target address in bits
     * @param state if true, sets the bit, otherwise clears it
     **/
    /*
    public void setBit(long address, boolean state)
	throws IOException
    {
	long relativeAddress = getRelative(address);
	if(!hasBit(relativeAddress)) {
	    return; // ignore
	}
	int position = Math.toIntExact(relativeAddress - windowStart);
	int bitPosition = position & 0x7;
	int bytePosition = position >> 3;
	byte bitMask = (byte)(1<<bitPosition);
	try(LockMap.Lock lock = lockMap.lock(bytePosition)) {
	    if(state) {
		data.bytes[bytePosition] |= bitMask;
	    } else {
		data.bytes[bytePosition] &= ~bitMask;
	    }
	}
    }
    */
    /**
     * Writes a bit into target address. Blocks if the underlying ParallelByteBuffer blocks.
     *
     * @param address target address in bits
     * @param state if true, sets the bit, otherwise clears it
     **/
    public void setBit(long address, boolean state)
    {
	throw new UnsupportedOperationException("Cannot write into ReadonlyBitFile.");
    }
    /*
	throws IOException
    {
	long byteAddress = Math.floorMod((address / 8), fileLength);
	try(LockMap.Lock myLock = byteLockMap.lock(byteAddress)) {
	    RandomAccessFile raf = threadLocalFile.get();
	    byte bitAddress = (byte)(LOW_BIT_MASK & address);
	    byte bitMaskOn = (byte)(1 << bitAddress);
	    byte bitMaskOff = (byte)(255 - bitMaskOn);
	    raf.seek(byteAddress);
	    byte currentByte = raf.readByte();
	    if(state) {
		currentByte |= bitMaskOn;
	    } else {
		currentByte &= bitMaskOff;
	    }
	    raf.seek(byteAddress);
	    raf.writeByte(currentByte);
	}
    }
    */
    /**
     * Testing methods
     **/
    /*
    private static void initializeTestFile(File f, long size)
	throws IOException
    {
	try(BufferedOutputStream bw = new BufferedOutputStream(new FileOutputStream(f))) {
	    for(long l = 0; l<size;l++) {
		bw.write(0);
	    }
	}
    }

    private static long addressTransformation(int i)
    {
	return
	    ((long)i)*i*i+((long)i)*i+i;
    }
    private static boolean RandomAccessWriteTest(File f)
    {
	final long fileLength = f.length();
	try (RandomAccessBitFile bitFile
	     = new RandomAccessBitFile(f)) {
	    Optional<IOException> oioe =
		IntStream.range(0,100000).parallel()
		.peek(i -> {
			if(0 == i%100) {
			    System.out.print(".");
			}
		    })
		.mapToObj(i -> {
			try {
			    bitFile.setBit(addressTransformation(i), 0 != Long.bitCount(addressTransformation(i)%fileLength)%2);
			    return null;
			} catch (IOException ioe) {
			    return ioe;
			}
		    })
		.filter(e -> null != e)
		.findAny();
	    if(oioe.isPresent()) {
		oioe.get().printStackTrace();
		return false;
	    }
	}
	catch (IOException closeException) {
	    closeException.printStackTrace();
	    return false;
	}
	return true;
    }

    private static boolean RandomAccessReadTest(File f)
    {
	final long fileLength = f.length();
	boolean result = true;
	try (RandomAccessBitFile bitFile = new RandomAccessBitFile(f)) {
	    result =
		IntStream.range(0,100000).parallel()
		.peek(i -> {
			if(0 == i%100) {
			    System.out.print(".");
			}
		    })
		.filter(i -> {
			try {
			    boolean bit = bitFile.getBit(addressTransformation(i));
			    if(bit && bit != (0 != Long.bitCount(addressTransformation(i)%fileLength)%2)) {
				System.out.println("at "+i+" there should have been "+Long.bitCount(addressTransformation(i)%fileLength)%2+" but there was "+(bit ? 1:0));
				return true; // found error
			    }
			    return false; // no error
			}
			catch (IOException ioe) {
			    ioe.printStackTrace();
			    return true;
			}
		    })
		.findAny().isPresent();
	    result = !result;
	}
	catch(IOException ioe) {
	    ioe.printStackTrace();
	    return false;
	}
	return result;
    }

    public static void main(String[] args)
	throws IOException
    {
	String testFileName = "test.tmp";
	long testFileLength = 10000l;
	for(String arg : args) {
	    try {
		testFileLength = Long.valueOf(arg);
	    }
	    catch(NumberFormatException nfe) {
		testFileName = arg;
	    }
	}
	File testFile = new File(testFileName);
	System.out.println("Testfile: '"+testFileName+"' "+testFileLength+" bytes.");
	initializeTestFile(testFile, testFileLength);
	
	int trials = 0;
	int successes = 0;

	trials++;
	if(RandomAccessWriteTest(testFile)) {
	    System.out.println("Test file write passed.");
	    successes++;
	}

	trials++;
	if(RandomAccessReadTest(testFile)) {
	    System.out.println("Test file read passed.");
	    successes++;
	}

	System.out.println(""+successes+"/"+trials+" tests succeeded.");
    }
    */
}
