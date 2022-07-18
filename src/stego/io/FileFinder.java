package stego.io;

import java.io.*;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.*;
import stego.ecc.*;
import stego.crypto.*;

/**
 * @author syy 2022-07-13
 **/

public class FileFinder
    implements AutoCloseable
{
    private RandomAccessBitFile bitfile;
    private volatile boolean isCancelled = false;
    public FileFinder(RandomAccessBitFile bitfile) {
        this.bitfile = bitfile;
    }
    public void close()
        throws IOException
    {
        //      this.bitfile.close();
    }
    public void cancel() {
        isCancelled = true;
    }
    public void uncancel() {
        isCancelled = false;
    }
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
    public InputStream find(char[] passcode)
        throws IOException
    {
        return find(passcode, 0);
    }
    public InputStream find(char[] passcode, int nonceSizeGuess)
        throws IOException
    {
        InputStream result = find(passcode, nonceSizeGuess, new SecureRandom());
        if(null != result) {
            return result;
        }
        int currentNonceSize = 0;
        if(nonceSizeGuess == currentNonceSize) {
            currentNonceSize++;
        }
        boolean found = false;
        while(!isCancelled && !found) {
            result = find(passcode, currentNonceSize, new SecureRandom());
            if(null == result) {
                currentNonceSize++;
                if(nonceSizeGuess == currentNonceSize) {
                    currentNonceSize++;
                }
            } else {
                found = true;
            }
        }
        return result;
    }
    public InputStream find(char[] passcode, int nonceBytes, SecureRandom random)
        throws IOException
    {
        byte[] nonceStartPoint = new byte[nonceBytes];
        random.nextBytes(nonceStartPoint);
        byte[] currentNonce = nonceStartPoint.clone();
        boolean found = false;
        boolean exhausted = false;
        byte[] metadata = new byte[Metadata.Field.size()];
        BaseStegoInputStream metaStream = null;
        Metadata treasure = null;
        while(!isCancelled && !found && !exhausted) {
            metaStream = new BaseStegoInputStream(bitfile,
                                              new CipherTrail(passcode, currentNonce),
                                              Metadata.Field.size(),
                                              Metadata.getMetadataArmorChain());
            int currentByte = 0;
            boolean matchSoFar = true;
            while(matchSoFar && (currentByte<Metadata.Field.RUNWAY.length())) {
                int result = metaStream.read();
                if(-1 == result) {
                    throw new IllegalStateException("StegoInputStream ended too soon.");
                }
                metadata[currentByte] = (byte)result;
                if(Metadata.RUNWAY_MARKER == metadata[currentByte]) {
                    currentByte++;
                } else {
                    matchSoFar = false;
                }
            }
            if(matchSoFar) {
                found = true;
                metaStream.read(metadata, currentByte, Metadata.Field.size()-currentByte);
                treasure = new Metadata(metadata);
                Arrays.fill(metadata, (byte)0);
            } else {
                exhausted = !incrementAndCheck(currentNonce, nonceStartPoint);
            }
            metaStream.close();
        }
        if(!found) {
            return null;
        }
        try {
            return
                new GZIPInputStream(
                                    new BaseStegoInputStream
                                    (bitfile,
                                     new CipherTrail(treasure.getKeyCopy()),
                                     treasure.getLength())
                                    );
        }
        finally {
            treasure.close();
        }
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
        try(FileFinder instance = new FileFinder(new RandomAccessBitFile(bitfile))) {
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
