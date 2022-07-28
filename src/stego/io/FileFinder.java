package stego.io;

import java.io.*;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.*;
import stego.ecc.*;
import stego.crypto.*;
import stego.util.CommandLineInterface;

/**
 * @author syy 2022-07-13
 **/

public class FileFinder
    implements AutoCloseable
{
    private LargeBitfield bitfile;
    private volatile boolean isCancelled = false;
    public FileFinder(LargeBitfield bitfile) {
	this.bitfile = bitfile;
    }
    public void close()
	throws IOException
    {
	//	this.bitfile.close();
    }
    public void cancel() {
	isCancelled = true;
    }
    public void uncancel() {
	isCancelled = false;
    }
    /*
    private boolean incrementAndCheck(byte[] current, byte[] target)
    {
	if(current.length != target.length) {
	    throw new IllegalArgumentException
		("current and target array length mismatch: "
		 +current.length+" != "+target.length);
	}
	boolean incremented = false;
	int currentByte = 0;
	while((!incremented) && (currentByte<current.length)) {
	    current[currentByte]++;
	    if(current[currentByte] != target[currentByte]) {
		incremented = true;
	    } else {
		currentByte++;
	    }
	}
	return incremented;
    }
    */
    public InputStream find(char[] passcode)
	throws IOException
    {
	return find(passcode, 0);
    }
    public InputStream find(char[] passcode, int nonceSizeGuess)
	throws IOException
    {
	return open(findMetadata(passcode, nonceSizeGuess));
    }
    public Metadata findMetadata(char[] passcode, int nonceSizeGuess)
	throws IOException
    {
	Metadata result = findMetadata(passcode, nonceSizeGuess, new SecureRandom());
	if(null != result) {
	    return result;
	}
	int currentNonceSize = 0;
	boolean found = false;
	while(!isCancelled && !found) {
	    if(nonceSizeGuess != currentNonceSize) {
		result = findMetadata(passcode, currentNonceSize, new SecureRandom());
		if(null != result) {
		    return result;
		}
	    }
	    currentNonceSize++;
	}
	return result;
    }
    //    public InputStream find(char[] passcode, int nonceBytes, SecureRandom random)
    public InputStream open(Metadata treasure)
	throws IOException
    {
	return
	    new GZIPInputStream(
				new BaseStegoInputStream
				(bitfile,
				 new CipherTrail(bitfile.getFileSalt(), treasure.getKey()),
				 treasure.getLength())
				);
    }
    public Metadata findMetadata(char[] passcode, int nonceBytes, SecureRandom random)
	throws IOException
    {
	Nonce nonceStartPoint = new Nonce(new byte[nonceBytes]);
	random.nextBytes(nonceStartPoint.bytes);
	Nonce currentNonce = new Nonce(nonceStartPoint.bytes.clone());
	boolean exhausted = false;
	Metadata treasure = null;
	while(!isCancelled && !exhausted) {
	    CommandLineInterface.showProgress();
	    try(BaseStegoInputStream metaStream = new BaseStegoInputStream(bitfile,
						  new CipherTrail(bitfile.getFileSalt(),passcode, currentNonce.bytes),
						  Metadata.Field.size(),
						      Metadata.getMetadataArmorChain())) {
		treasure = Metadata.read(metaStream);
		if(treasure.isValid()) {
		    return treasure;
		} else {
		    exhausted = !currentNonce.incrementAndCheck(nonceStartPoint);
		}
	    }
	}
	return null;
    }

    public static void main(String[] arg)
	throws Exception
    {
	if(arg.length != 2) {
	    System.out.println("Test usage:");
	    System.out.println("<bitfile> <sourcefile>");
	}
	
	File bitfile = new File(arg[0]);
	
	if(!bitfile.exists()) {
	    System.out.println("bitfile '"+arg[0]+"' does not exist.");
	    return;
	}
	try(FileFinder instance = new FileFinder(new ReadonlyBitFile(bitfile.length(), FileUtil.createInputStreamSupplier(bitfile)))) {
	    System.out.println("file");
	    try(InputStream in = instance.find(arg[1].toCharArray(),0)) {
		if(null != in) {
		    try(FileOutputStream fos = new FileOutputStream(new File(arg[1]))) {
			byte[] buffer = new byte[1024];
			int result = in.read(buffer);
			while(-1 != result) {
			    System.err.println("read "+result+" bytes.");
			    fos.write(buffer, 0, result);
			    result = in.read(buffer);
			}
			System.err.println("read "+result+" bytes.");
		    }
		} else {
		    System.err.println("Could not find "+arg[1]);
		}
	    }
	}
    }

}
