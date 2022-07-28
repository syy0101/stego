package stego.io;

import java.io.*;
import java.nio.*;
import java.util.*;
import java.util.stream.*;
import stego.ecc.*;
import stego.crypto.*;

public class BaseStegoInputStream
    extends InputStream
{
    private LargeBitfield bitfield;
    private ArmorCoder armorer;
    private final byte[] data;
    private ByteBuffer dataBuffer;
    private long unread;
    private long readBits = 0l;
    private final CipherTrail cipherTrail;
    public BaseStegoInputStream(LargeBitfield bitfield, CipherTrail source, long length)
    {
	this(bitfield, source, length, ArmorCoder.getDefaultChain());
    }
    public BaseStegoInputStream(LargeBitfield bitfield, CipherTrail source, long length,
			    ArmorCoder armorer)
    {
	this.bitfield = bitfield;
	this.cipherTrail = source;
	this.unread = length;
	this.armorer = armorer;
	this.data = new byte[armorer.sourcePacketSize()];
	
	this.dataBuffer = ByteBuffer.wrap(data);
	dataBuffer.position(dataBuffer.limit());
    }
    private void clearInternalData()
    {
	this.bitfield = null; // GC hint
	Arrays.fill(data, (byte)0);
	readBits = 0l;
	dataBuffer.rewind();
	dataBuffer.limit(0);
	unread = 0l;
    }
    public boolean markSupported()
    {
	return false;
    }
    public void reset()
	throws IOException
    {
	throw new IOException("reset() is not supported in StegoInputStream.");
    }
    public long skip(long n)
	throws IOException
    {
	throw new IOException("skip(long) is not supported in StegoInputStream.");
    }
    public void close()
	throws IOException
    {
	clearInternalData();
	super.close();
    }
    public int available()
    {
	return Math.max(dataBuffer.remaining(), (unread > 0)?1:0);
    }
    public int read()
	throws IOException
    {
	byte[] buffer = new byte[1];
	int result = read(buffer);
	if(result == 1) {
	    result = Byte.toUnsignedInt(buffer[0]);
	    buffer[0] = (byte)0;
	    return result;
	}
	return -1;
    }
    public int read(byte[] b)
	throws IOException
    {
	return read(b, 0, b.length);
    }
    public int read(byte[] b, int off, int len)
	throws IOException
    {
	if(null == b) {
	    throw new NullPointerException("Tried to read into null array.");
	}
	if((off<0) || (len<0) || (len > b.length-off)) {
	    throw new IndexOutOfBoundsException
		("(("+off+"<0) || ("+len+"<0) || ("+len+" > "+(b.length-off)+"))");
	}
	int targetLen = Math.toIntExact(Math.min(unread+dataBuffer.remaining(), len));
	int readCount = 0;
	while((targetLen>0) && (available()>0)) {
	    if(dataBuffer.remaining()<1) {
		internalFillReadBuffer();
	    }
	    int byteAmount = Math.min(targetLen, dataBuffer.remaining());
	    dataBuffer.get(b, off, byteAmount);
	    off += byteAmount;
	    targetLen -= byteAmount;
	    len -= byteAmount;
	    readCount += byteAmount;
	}
	if(readCount > 0) {
	    return readCount;
	}	
	if(!(available()>0)) {
	    return -1;
	}
	return readCount;
    }
    private void internalFillReadBuffer()
	throws IOException
    {
	byte[] armoredData = new byte[armorer.sourcePacketSize()];
	int targetsRequired = armoredData.length*8;
	//List<CipherHop> targets = new ArrayList<CipherHop>(targetsRequired*8);
	List<CipherHop> targets = new ArrayList<CipherHop>(targetsRequired);
	while(targetsRequired > 0) {
	    List<CipherHop> targetCandidates = cipherTrail.findBlocksHops(readBits);
	    final int actualNewTargets = Math.min(targetCandidates.size(), targetsRequired);
	    List<CipherHop> newTargets = targetCandidates.subList(0, actualNewTargets);
	    targets.addAll(newTargets);
	    targetsRequired -= actualNewTargets;
	    readBits += actualNewTargets;
	}
	List<IOException> ioeList
	    = IntStream.range(0, armoredData.length)
	    .parallel()
	    .mapToObj(targetByte -> {
		    int result = (byte)0;
		    ArrayList<IOException> ioel = new ArrayList<IOException>(8);
		    for(int targetBit = 0; targetBit<8;targetBit++) {
			int targetMask = 1 <<targetBit;
			CipherHop target = targets.get(targetByte*8+targetBit);
			try {
			    if(target.cipherBit ^ bitfield.getBit(target.address)) {
				result |= targetMask;
			    }
			}
			catch(IOException ioe) {
			    ioel.add(ioe);
			}
		    }
		    armoredData[targetByte] = (byte)result;
		    result = 0;
		    return ioel;
		})
	    .flatMap(l -> l.stream())
	    .filter(e -> null != e)
	    .collect(Collectors.toList());
	Arrays.fill(data, (byte)0);
	try (DecodedPacket decodeSource = new DecodedPacket(armoredData)) {
	    try (DecodedPacket decodeResult = armorer.decodeChain(decodeSource)) {
		byte[] decodedData = decodeResult.getRawPacket();
		dataBuffer.rewind();
		dataBuffer.put(decodedData);
		Arrays.fill(decodedData, (byte)0);
		dataBuffer.rewind();
		dataBuffer.limit(Math.toIntExact(Math.min(unread, decodedData.length)));
		unread -= dataBuffer.limit();
	    }
	}
	

	Arrays.fill(armoredData, (byte)0);
	if(!ioeList.isEmpty()) {
	    IOException firstException = ioeList.remove(0);
	    while(!ioeList.isEmpty()) {
		firstException.addSuppressed(ioeList.remove(0));
	    }
	    throw firstException;
	}
	
    }
}
