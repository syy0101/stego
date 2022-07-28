package stego.io;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.Consumer;
import java.util.zip.GZIPOutputStream;
import stego.crypto.*;
import stego.ecc.*;

/**
 * FileHider writes data into bitfiles onto trails that are findable only by the name of the trail.
 *
 * The contents written to the stream are first gzipped and then armored, encrypted and written by {@link BaseStegoOutputStream}.
 * When the main stream is closed, the amount of gzipped and armored data and the location key that was used for its {@link stego.crypto.CipherTrail}
 * are written as a {@link Metadata} into trail that is got from the name of the stream and a random nonce whose size is random amount of bytes.
 *
 * {@link FileFinder} can find the {@link Metadata} with the name by bruteforcing the nonce and testing if such combination would yield
 * a {@link stego.crypto.CipherTrail} which would start with {@link Metadata RUNWAY_MARKER}, and after finding, opening the trail the {@link Metadata} points to for reading.
 *
 * @author syy 2022-07-04 2022-07-13 2022-07-15 2022-07-24
 **/
public class FileHider
    implements AutoCloseable,
	       Consumer<LargeBitfield>
{
    private final File plainfile;
    private MetadataHider metadataHider = null;
    private Metadata metadata = null;
    private final int minimumNonceBytes;
    private final SecureRandom random;
    //private byte[] nonce;
    public FileHider(File plainfile, int minimumNonceBytes, SecureRandom random)
    {
	this.plainfile = plainfile;
	metadata = Metadata.createMetadata(random, -1l);
	this.minimumNonceBytes = minimumNonceBytes;
	this.random = random;
    }
    public void accept(LargeBitfield bitfield)
    {
	try {
	    writeData(bitfield);
	    metadataHider.accept(bitfield);
	}
	catch(IOException ioe) {
	    throw new UncheckedIOException(ioe);
	}
    }
    
    public void close()
    {
	metadata.close();
	//Arrays.fill(nonce, (byte)0);
	//	nonce = null;
    }

    public static final int BUFSIZE = 1024*1024;
    private void writeData(LargeBitfield bitfield)
	throws IOException
    {
	try(FileInputStream in = new FileInputStream(this.plainfile)) {
	    try(GuardedByteArray buffer = new GuardedByteArray(new byte[BUFSIZE])) {
		try(GuardedByteArray datakey = metadata.getKey()) {
		    BaseStegoOutputStream stego = null;
		    try(BaseStegoOutputStream stegoOut = new BaseStegoOutputStream(bitfield, new CipherTrail(bitfield.getFileSalt(), datakey))) {
			try(GZIPOutputStream defStream = new GZIPOutputStream(stegoOut, BUFSIZE, true)) {
			    int readBytes;
			    do {
				readBytes = in.read(buffer.bytes);
				if(readBytes > 0) {
				    defStream.write(buffer.bytes, 0, readBytes);
				}
			    } while(readBytes > 0);
			    defStream.flush();
			}
			stego = stegoOut;
		    }
		    if(null == this.metadataHider) {
			Metadata completeMetadata = new Metadata(metadata.getKeyCopy(), stego.getLength());
			metadata.close();
			metadata = completeMetadata;
			this.metadataHider = new MetadataHider(metadata, plainfile.getName().toCharArray(), minimumNonceBytes, random);
		    }
		}
	    }
	}
    }
}
