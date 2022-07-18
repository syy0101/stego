package stego.io;

import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.GZIPOutputStream;
import stego.crypto.*;
import stego.ecc.*;

/**
 * StegoOutputStream writes data into bitfiles onto trails that are findable only by the name of the trail.
 *
 * The contents written to the stream are first gzipped and then armored, encrypted and written by {@link BaseStegoOutputStream}.
 * When the main stream is closed, the amount of gzipped and armored data and the location key that was used for its {@link stego.crypto.CipherTrail}
 * are written as a {@link Metadata} into trail that is got from the name of the stream and a random nonce whose size is random amount of bytes.
 *
 * {@link FileFinder} can find the {@link Metadata} with the name by bruteforcing the nonce and testing if such combination would yield
 * a {@link stego.crypto.CipherTrail} which would start with {@link Metadata RUNWAY_MARKER}, and after finding, opening the trail the {@link Metadata} points to for reading.
 *
 * @author syy 2022-07-04 2022-07-13 2022-07-15
 **/
public class StegoOutputStream
    extends GZIPOutputStream
{
    public static final int BUFSIZE = 1024*1024;
    public static final int DEFAULT_MINIMUM_NONCE_SIZE = 1;

    /**
     * Closes the stream and the underlying compression and BaseStegoOutput streams, writes metadata and clears internal data.
     *
     * @throws IOException in case underlying operation throws such.
     **/
    public void close()
        throws IOException
    {
        super.close();
        writeMetadata();
        clearInternalData();
    }

    /**
     * Opens a StegoOutputStream for writing into bitfile and stores the key of trail to metadata trail near passcode at random nonce difference.
     * Nonce bytesize is randomly decided and is minimumNonceSize + count of first continuous 1s from random.
     * NOTE that the metadata is written at closing of the returned stream.
     *
     * @param bitfile to write to
     * @param passcode typically the name of the source
     * @param minimumNonceSizeBytes at least this many random bytes are given as extra salt bytes to CipherTrail
     * @param random the randomness source to use in this StegoOutputStream opening
     * 
     * @returns opened StegoOutputStream
     *
     * @throws IOException in case IOException happens in underlying operations
     **/
    public static StegoOutputStream open(RandomAccessBitFile bitfile, char[] passcode, int minimumNonceSizeBytes, SecureRandom random)
        throws IOException
    {
        byte[] datakey = new byte[Metadata.Field.KEY.length];
        random.nextBytes(datakey);

        return new StegoOutputStream(bitfile, passcode.clone(), datakey, getNonceSizeBytes(minimumNonceSizeBytes, random));
    }

    public static StegoOutputStream open(RandomAccessBitFile bitfile, char[] passcode, int minimumNonceSizeBytes)
        throws IOException
    {
        return open(bitfile, passcode, minimumNonceSizeBytes, new SecureRandom());
    }

    /**
     * Hides a filesystem file into the bitfile using the file name as its passcode.
     *
     * @param bitfile to write to
     * @param inFile source file
     * @param random the randomness source to use in this StegoOutputStream operation
     *
     * @throws IOException in case IOException happens in underlying operations
     **/
    public static void hide(RandomAccessBitFile bitfile, File inFile, SecureRandom random)
        throws IOException
    {
        char[] passcode = inFile.getName().toCharArray();
        try {
            try(FileInputStream in = new FileInputStream(inFile)) {
                hide(bitfile, passcode, DEFAULT_MINIMUM_NONCE_SIZE, random, in);
            }
        }
        finally {
            Arrays.fill(passcode,' ');
        }
    }

    /**
     * Hides a filesystem file into the bitfile using the file name as its passcode.
     *
     * @param bitfile to write to
     * @param passcode typically the name of the source
     * @param minimumNonceSizeBytes at least this many random bytes are given as extra salt bytes to CipherTrail
     * @param random the randomness source to use in this StegoOutputStream opening
     * @param in InputStream whose contents are stored into bitfile with StegoOutputStream
     *
     * @throws IOException in case IOException happens in underlying operations
     **/
    public static void hide(RandomAccessBitFile bitfile, char[] passcode, int minimumNonceSizeBytes, SecureRandom random, InputStream in)
        throws IOException
    {
        byte[] buffer = new byte[BUFSIZE];
        try(StegoOutputStream defStream = StegoOutputStream.open(bitfile, passcode, minimumNonceSizeBytes, random)) {
            int readBytes;
            do {
                readBytes = in.read(buffer);
                if(readBytes > 0) {
                    defStream.write(buffer, 0, readBytes);
                    defStream.flush();
                }
            } while(readBytes > 0);
        }
        finally {
            Arrays.fill(buffer,(byte)0);
        }
    }

    /**
     * Internal state data and private methods.
     **/
    private RandomAccessBitFile bitfile;
    private char[] passcode;
    private byte[] datakey;
    private int nonceSizeBytes;

    private void clearInternalData()
    {
        Arrays.fill(passcode, ' ');
        Arrays.fill(datakey, (byte)0);
        nonceSizeBytes = 0;
        bitfile = null;
    }

    private StegoOutputStream(RandomAccessBitFile bitfile, char passcode[], byte[] datakey, int nonceSizeBytes)
        throws IOException
    {
        super(new BaseStegoOutputStream(bitfile, new CipherTrail(datakey)), BUFSIZE, true);
        this.bitfile = bitfile;
        this.passcode = passcode;
        this.datakey = datakey;
        this.nonceSizeBytes = nonceSizeBytes;
    }

    /**
     * Gives a random number which is the count of continuous trues from SecureRandom
     *
     * @param minimumNonceSizeBytes base minimum nonce size
     * @param random the SecureRandom which bits are got from
     * @returns minimumNonceSizeBytes + count of continuous 1s/trues from random
     **/
    private static int getNonceSizeBytes(int minimumNonceSizeBytes, SecureRandom random)
    {
        int result = minimumNonceSizeBytes;
        while(random.nextBoolean()) {
            result++;
        }
        return result;
    }

    /**
     * Writes the metadata block into the bitfile. Run when closing the stream.
     *
     * @throws IOException in case IOException happens during operation.
     **/
    private void writeMetadata()
        throws IOException
    {
        long datalength = ((BaseStegoOutputStream)(super.out)).getLength();

        // second write metadata to bitfile
        try(Metadata metadata = new Metadata(datakey, datalength)) {
            Arrays.fill(datakey, (byte)0);
            datalength = -1l;

            CipherTrail metaTrail = new CipherTrail(passcode, nonceSizeBytes);

            try(BaseStegoOutputStream metaStream = new BaseStegoOutputStream(bitfile, metaTrail, Metadata.getMetadataArmorChain())) {
                byte[] metaBytes = metadata.getByteCopy();
                try {
                    metaStream.write(metaBytes);
                }
                finally {
                    Arrays.fill(metaBytes, (byte)0);
                }
            }
        }
    }

    /**
     * Testing methods.
     **/
    
    /**
     * A simple main method for testing functionality and to operate basic functionality from command line.
     *
     * @param arg arg[0] should contain the filename of the bitfile and arg[1] should contain filename of source file. If bitfile does not exist, such will be created.
     *
     * @throws Exception testing method throws all exceptions.
     **/
    public static void main(String[] arg)
        throws Exception
    {
        if(arg.length != 2) {
            System.out.println("Test usage:");
            System.out.println("<bitfile> <sourcefile>");
        }
        File bitfile = new File(arg[0]);
        File infile = new File(arg[1]);
        if(!infile.exists()) {
            System.out.println("infile '"+arg[1]+"' does not exist.");
            return;
        }
        if(!bitfile.exists()) {
            System.out.println("creating '"+arg[0]);
            RandomAccessBitFile.createNewBitFile(bitfile, 1024*1024*10, new SecureRandom());
        }
        StegoOutputStream.hide(new RandomAccessBitFile(bitfile), infile, new SecureRandom());
    }
}
