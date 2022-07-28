package stego.io;

import java.io.*;
import java.nio.*;
import java.util.*;
import java.util.stream.*;
import stego.ecc.ArmorCoder;
import stego.crypto.*;
import java.util.AbstractMap.SimpleImmutableEntry;

public class BaseStegoOutputStream extends OutputStream
{
    private LargeBitfield bitfield;
    private ArmorCoder armorer = ArmorCoder.getDefaultChain();
    private byte[] data = new byte[armorer.maxData()];
    private ByteBuffer dataBuffer = ByteBuffer.wrap(data);
    private long length = 0l;
    private long writtenBits = 0l;
    private final CipherTrail cipherTrail;
    private void clearInternalData()
    {
	Arrays.fill(data, (byte)0);
	writtenBits = 0l;
    }
    public BaseStegoOutputStream(LargeBitfield bitfield, CipherTrail target)
    {
	this.bitfield = bitfield;
	this.cipherTrail = target;
    }
    public BaseStegoOutputStream(LargeBitfield bitfield, CipherTrail target, ArmorCoder armorer)
    {
	this.bitfield = bitfield;
	this.cipherTrail = target;
	this.armorer = armorer;
    }
    public long getLength()
    {
	return length;
    }
    public void close()
	throws IOException
    {
	internalFlushAndRewind();
	clearInternalData();
	super.close();
    }
    private void internalFlushAndRewind()
	throws IOException
    {
	int inputSize = dataBuffer.position();
	if(inputSize <1) {
	    return;
	}
	length += inputSize;
	byte[] inputBlock = new byte[inputSize];
	dataBuffer.rewind();
	dataBuffer.get(inputBlock, 0, inputSize);
	dataBuffer.rewind();

	byte[] armored = armorer.encodeChain(inputBlock);
	Arrays.fill(inputBlock, (byte)0);
	inputBlock = null;

	List<CipherHop> targets = new ArrayList<CipherHop>(armored.length*8);
	int targetsRequired = armored.length*8;
	while(targetsRequired > 0) {
	    List<CipherHop> targetCandidates = cipherTrail.findBlocksHops(writtenBits);
	    final int actualNewTargets = Math.min(targetCandidates.size(), targetsRequired);
	    List<CipherHop> newTargets = targetCandidates.subList(0, actualNewTargets);
	    targets.addAll(newTargets);
	    targetsRequired -= actualNewTargets;
	    writtenBits += actualNewTargets;
	}

	List<IOException> ioeList
	    = IntStream.range(0, armored.length*8)
	    .parallel()
	    .mapToObj(bitNumber -> {
		    CipherHop target = targets.get(bitNumber);
		    int targetByte = bitNumber / 8;
		    int targetBit = bitNumber % 8;
		    int targetMask = 1 << targetBit;
		    boolean dataBit =( 0 != (armored[targetByte] & targetMask));
		    try {
			bitfield.setBit(target.address, target.cipherBit ^ dataBit);
		    }
		    catch(IOException ioe) {
			return ioe;
		    }
		    return null;
		})
	    .filter(e -> null != e)
	    .collect(Collectors.toList());
	Arrays.fill(armored, (byte)0);
	if(!ioeList.isEmpty()) {
	    IOException firstException = ioeList.remove(0);
	    while(!ioeList.isEmpty()) {
		firstException.addSuppressed(ioeList.remove(0));
	    }
	    throw firstException;
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
	if(null == b) {
	    throw new NullPointerException();
	}
	if((off < 0) || (len < 0) || ((off+len) > b.length)) {
	    throw new IndexOutOfBoundsException("("+off+" < 0) || ("+len+" < 0) || (("+off+"+"+len+") > "+b.length+"))");
	}
	while(len > 0) {
	    int blockSize = Math.min(dataBuffer.remaining(), len);
	    dataBuffer.put(b, off, blockSize);
	    if(!dataBuffer.hasRemaining()) {
		internalFlushAndRewind();
	    }
	    len -= blockSize;
	    off += blockSize;
	}
    }
    public void write(int b)
	throws IOException
    {
	byte[] myBuffer = new byte[1];
	myBuffer[0] = (byte)b;
	write(myBuffer,0,1);
	Arrays.fill(myBuffer, (byte)0);
    }
}
