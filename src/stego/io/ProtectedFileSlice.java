package stego.io;

import java.io.*;
import java.util.*;
import java.util.function.Consumer;
import java.security.SecureRandom;

import stego.crypto.*;
import stego.util.CommandLineInterface;

public class ProtectedFileSlice implements LargeBitfield, AutoCloseable
{
    private final GuardedByteArray data;
    private final LockMap<Integer> lockMap = new LockMap<Integer>();

    private final long windowStart;
    private final long windowEnd;
    //private final long outerDataSize;
    private final long innerDataSize;
    private final ReadonlyBitFile innerReadonlyBitFile;
    private final OutputStream out;
    private final FileSalt fileSalt;

    public FileSalt getFileSalt()
    {
	return fileSalt;
    }
    public ProtectedFileSlice(ReadonlyBitFile openedInFile,
			      //Metadata opener,
			      OutputStream out, long windowStart, long windowEnd, FileSalt outputFileSalt)
	throws IOException
    {
	this.windowStart = windowStart;
	this.windowEnd = windowEnd;
	//this.outerDataSize = inFile.dataLength;
	//this.innerDataSize = openedInFile.dataLength;
	this.out = out;
	this.fileSalt = outputFileSalt;

	this.data = new GuardedByteArray(new byte[Math.toIntExact(windowEnd-windowStart)]);
	//innerReadonlyBitFile = inFile.openInnerReadonlyBitFile(opener);
	this.innerReadonlyBitFile = openedInFile;
	this.innerDataSize = innerReadonlyBitFile.dataLength;
	try(InputStream in = innerReadonlyBitFile.get()) {
	    in.skip(windowStart);
	    in.read(data.bytes);
	}
    }

    public ProtectedFileSlice(SecureRandom random, OutputStream out, long windowStart, long windowEnd,
			      //long outerSize,
			      long innerDataSize,
			      FileSalt outputFileSalt)
    {
	this.windowStart = windowStart;
	this.windowEnd = windowEnd;
	//this.outerDataSize = outerSize-FileSalt.SIZE;
	this.innerDataSize = innerDataSize;
	this.out = out;
	this.fileSalt = outputFileSalt;

	this.data = new GuardedByteArray(new byte[Math.toIntExact(windowEnd-windowStart)]);
	innerReadonlyBitFile = null;
	//this.innerDataSize = this.outerDataSize -FileSalt.SIZE;
	random.nextBytes(data.bytes);
    }
    public void close()
	throws IOException
    {
	lockMap.close();
	out.write(data.bytes);
	data.close();
    }

    /**
     * Reads a bit in the address modulo size bits. 
     * If address is within this slice, returns possibly changed bit.
     * If address is outside this slice, returns the bit
     * from the underlying ReadonlyBitFile if such exists.
     * If neither is possible, throws IllegalStateException.
     *
     * @param address target address
     * @return state of bit in address
     **/
    public boolean getBit(long address)
	throws IOException
    {
	long relativeAddress = getRelative(address);
	if(hasBit(relativeAddress)) {
	    int position = Math.toIntExact(relativeAddress - windowStart);
	    int bitPosition = position & 0x7;
	    int bytePosition = position >> 3;
	    byte bitMask = (byte)(1<<bitPosition);
	    try(LockMap.Lock myLock = lockMap.lock(bytePosition)) {
		return 0 != (data.bytes[bytePosition] & bitMask);
	    }
	}
	if(null != innerReadonlyBitFile) {
	    return innerReadonlyBitFile.getBit(address);
	}
	throw new IllegalStateException("tried to read without data backing.");
    }

    /**
     * Makes the target address relative to the data area of which this slice is a slice of.
     *
     * @return relative address, which may be outside this slice.
     **/
    private long getRelative(long address)
    {
	long relativeAddress = Math.floorMod(address, innerDataSize);
	return relativeAddress;
    }

    /**
     * Checks if the target address is within this slice.
     *
     * @return if the target address is within this slice.
     **/
    public boolean hasBit(long address)
    {
	long relativeAddress = getRelative(address);
	if(relativeAddress < windowStart)
	    return false;
	if(relativeAddress < windowEnd)
	    return true;
	return false;
    }
    
    /**
     * Writes a bit into target address.
     * If the address ends outside this slice, it is ignored.
     *
     * @param address target address in bits
     * @param state if true, sets the bit, otherwise clears it
     **/
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

    /**
     * Creates a bitfile filled with randomness overwritten by the given BaseStegoOutputStreams.
     * Iterates piece by piece of garbage collecting, generating memory source file contents,
     * changing the memory to incorporate the steganographic changes that target that slice,
     * and then writing the changed slice into the new bitfile encrypted.
     *
     * @param dataSize size of target data output
     * @param destination the OutputStream to which contents are encrypted and written to
     * @param closingPasscode user inserted passcode to which the resulting bitfile will be encrypted to
     * @param minimumNonceSize how many bytes tailing must be at least of
     * @param random the SecureRandom from which to take relevant random bytes from
     * @param writers collection of writers who should create and write their BaseStegoOutputStreams into the given ProtectedFileSlice
     *
     * @throws IOException if IOException occurs while operating
     **/
    public static Metadata createAndWrite(long dataSize,
					  OutputStream destination,
					  char[] closingPasscode,
					  int minimumNonceSize,
					  SecureRandom random,
					  Collection<? extends Consumer<? super LargeBitfield>> writers)
	throws IOException
    {
	final int sliceSize = getSliceSize();
	
	try(FileSalt outputFileSalt = new FileSalt(random)) {
	    Metadata destinationMetadata = Metadata.createMetadata(random, dataSize);
	    
	    try(Nonce nonce = new Nonce(random,minimumNonceSize)) {
		try(Metadata cipheredMetadata = destinationMetadata.cipher(outputFileSalt, closingPasscode, nonce.bytes)) {
		    destination.write(cipheredMetadata.bytes);
		    destination.write(outputFileSalt.bytes);
		    try(GuardedByteArray destinationKey = destinationMetadata.getKey()) {
			try(CipherTrailOutputStream cipheredDestinationStream
			    = new CipherTrailOutputStream(destination,
							  new CipherTrail(outputFileSalt, destinationKey))) {
			    try(FileSalt innerBitFileSalt = new FileSalt()) {
				cipheredDestinationStream.write(innerBitFileSalt.bytes);
				long start = 0l;
				long end = Math.min(start+sliceSize, dataSize);
				while(start<dataSize) {
				    System.gc(); // run garbage collection because memory heavy operation in this loop.
				    try(ProtectedFileSlice currentSlice
					= new ProtectedFileSlice(random,
								 cipheredDestinationStream,
								 start, end, dataSize, innerBitFileSalt)) {
					for(Consumer<? super LargeBitfield> currentTarget : writers) {
					    try {
						currentTarget.accept(currentSlice);
						//currentTarget.accept((LargeBitfield)cb);
					    }
					    catch(UncheckedIOException e) {
						throw new IOException(e);
					    }
					}
				    }
				    start = end;
				    end = Math.min(start+sliceSize, dataSize);
				}
			    }
			}
		    }
		}
		return destinationMetadata;
	    }
	}
    }
    /**
     * @return 1/4 of either maximum memory we have or Integer.MAX_VALUE, which ever is smaller of them.
     **/
    public static int getSliceSize()
    {
	return Math.toIntExact(Math.min(Runtime.getRuntime().maxMemory(), Integer.MAX_VALUE) / 4); // safe maximum array size
    }
    /*
    private static void trackOutputPosition(OutputStream out)
    {
	try {
	    if(out instanceof FileOutputStream) {
		new Exception("p:"+((FileOutputStream)out).getChannel().position()).printStackTrace();
	    } else {
		new Exception("not a FileOutputStream: "+out).printStackTrace();
	    }
	}
	catch(IOException ioe) {
	    throw new IllegalStateException(ioe);
	}
    }
    */
    /**
     * Iterates piece by piece of garbage collecting, reading and decrypting into memory source file contents,
     * changing the memory to incorporate the steganographic changes that target that slice,
     * and then writing the changed slice into the new bitfile encrypted.
     *
     * @param openedInnerBitfile the opened ReadonlyBitFile which the contents are read and decrypted from
     * @param destination the OutputStream to which contents are encrypted and written to
     * @param closingPasscode user inserted passcode to which the resulting bitfile will be encrypted to
     * @param minimumNonceSize how many bytes tailing must be at least of
     * @param random the SecureRandom from which to take relevant random bytes from
     * @param writers collection of writers who should create and write their BaseStegoOutputStreams into the given ProtectedFileSlice
     *
     * @throws IOException if IOException occurs while operating
     **/
    public static Metadata write(ReadonlyBitFile openedInnerBitfile,
				 //Metadata inputMetadata,
				 OutputStream destination,
				 char[] closingPasscode,
				 int minimumNonceSize,
				 SecureRandom random,
				 Collection<? extends Consumer<? super LargeBitfield>> writers)
	throws IOException
    {
	final int sliceSize = getSliceSize();
	try(FileSalt outputFileSalt = new FileSalt(random)) {
	    Metadata destinationMetadata = Metadata.createMetadata(random, openedInnerBitfile.dataLength);
	    try(Nonce nonce = new Nonce(random,minimumNonceSize)) {
		try(Metadata cipheredMetadata = destinationMetadata.cipher(outputFileSalt, closingPasscode, nonce.bytes)) {
		    destination.write(cipheredMetadata.bytes);
		    destination.write(outputFileSalt.bytes);
		    try(GuardedByteArray destinationKey = destinationMetadata.getKey()) {
			try(CipherTrailOutputStream cipheredDestinationStream
			    = new CipherTrailOutputStream(destination,
							  new CipherTrail(outputFileSalt, destinationKey))) {
			    FileSalt innerBitFileSalt = openedInnerBitfile.getFileSalt();
			    cipheredDestinationStream.write(innerBitFileSalt.bytes);
			    long start = 0l;
			    long end = Math.min(start+sliceSize, openedInnerBitfile.dataLength);
			    while(start<openedInnerBitfile.dataLength) {
				CommandLineInterface.showProgress();
				System.gc(); // run garbage collection because memory heavy operation in this loop.
				try(ProtectedFileSlice currentSlice
				    = new ProtectedFileSlice(openedInnerBitfile,
							     //inputMetadata,
							     cipheredDestinationStream,
							     start, end, outputFileSalt)) {
				    for(Consumer<? super ProtectedFileSlice> currentTarget : writers) {
					try {
					    currentTarget.accept(currentSlice);
					}
					catch(UncheckedIOException e) {
					    throw new IOException(e);
					}
				    }
				}
				start = end;
				end = Math.min(start+sliceSize, openedInnerBitfile.dataLength);
			    }
			}
		    }
		}
		return destinationMetadata;
	    }
	}
    }
}
