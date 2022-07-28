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
public class MetadataHider
    implements Consumer<LargeBitfield>, AutoCloseable
{
    private Metadata metadata;
    private char[] passcode;
    private Nonce nonce;
    //private byte[] nonce;
    public MetadataHider(Metadata metadata, char[] passcode, int minimumNonceSize, SecureRandom random)
    {
	this.passcode = passcode;
	this.metadata = metadata;
	this.nonce = new Nonce(random, minimumNonceSize);
	//this.nonce = new byte[getNonceSizeBytes(minimumNonceSize, random)];
	//random.nextBytes(nonce);
    }
    public MetadataHider(Metadata metadata, char[] passcode, byte[] nonce)
    {
	this.passcode = passcode;
	this.metadata = metadata;
	this.nonce = new Nonce(nonce);
    }
    public void accept(LargeBitfield bitfield)
    {
	try {
	    writeMetadata(bitfield);
	}
	catch(IOException ioe) {
	    throw new UncheckedIOException(ioe);
	}
    }

    public void close()
    {
	try {
	    try {
		metadata.close();
	    }
	    finally {
		nonce.close();
		nonce = null;
	    }
	}
	finally {
	    Arrays.fill(passcode, ' ');
	}
    }

    private void writeMetadata(LargeBitfield bitfield)
	throws IOException
    {
	CipherTrail metaTrail = new CipherTrail(bitfield.getFileSalt(), passcode, nonce.bytes, false);

	try(BaseStegoOutputStream metaStream = new BaseStegoOutputStream(bitfield, metaTrail, Metadata.getMetadataArmorChain())) {
	    byte[] metaBytes = metadata.getByteCopy();
	    try {
		metaStream.write(metaBytes);
	    }
	    finally {
		Arrays.fill(metaBytes, (byte)0);
	    }
	}
    }

    /**
     * Gives a random number which is the count of continuous trues from SecureRandom
     *
     * @param minimumNonceSizeBytes base minimum nonce size
     * @param random the SecureRandom which bits are got from
     * @returns minimumNonceSizeBytes + count of continuous 1s/trues from random
     **/
    /*
    public static int getNonceSizeBytes(int minimumNonceSizeBytes, SecureRandom random)
    {
	int result = minimumNonceSizeBytes;
	while(random.nextBoolean()) {
	    result++;
	}
	return result;
    }
    */
}
