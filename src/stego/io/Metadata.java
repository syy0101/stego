package stego.io;

import java.util.*;
import java.nio.*;
import stego.ecc.*;

public class Metadata
    implements AutoCloseable
{
    public static final byte RUNWAY_MARKER = (byte)255; // Nothing in my sleeve -constant, but should not be 0 because java new array is filled with 0
    public enum Field
    {
        RUNWAY(8), // all bits here are 1
        KEY(32), // CipherTrail key
        LENGTH(Long.BYTES); // CipherTrail length
        public int start() {
            int start = 0;
            for(Field f : values()) {
                if(f.equals(this)) {
                    break;
                }
                start += f.length;
            }
            return start;
        }
                
        public final int length;
        public int length() {
            return length;
        }
        public int end()
        {
            return start()+length;
        }

        public static int size()
        {
            int size = 0;
            for(Field f : values()) {
                size += f.length;
            }
            return size;
        }
        //      private static int totalSize = 0;
        private Field(int length)
        {
            //      this.start = totalSize;
            this.length = length;
            //totalSize += length;
            //this.end = totalSize;
        }
    }
    public static ArmorCoder getMetadataArmorChain()
    {
        ArmorCoder result =
            new ReedSolomonCoder(Field.size())
            .setNext(new HammingCoder());
        return result;
    }

    /**
     * Internal contents are stored in basedata, which is cleared in close().
     **/
    private final byte[] basedata = new byte[Field.size()];
    public long getLength()
    {
        return
            ByteBuffer.wrap(basedata).getLong(Field.LENGTH.start());
    }
    /**
     * @returns copy of key material in a new byte[]. Receiver is responsible of clearing the received buffer after use.
     **/
    public byte[] getKeyCopy()
    {
        byte[] result = new byte[Field.KEY.length];
        System.arraycopy(basedata, Field.KEY.start(), result, 0, Field.KEY.length);
        return result;
    }
    /**
     * @returns a copy of the internal packet. Caller is responsible for clearing the received array.
     **/
    public byte[] getByteCopy()
    {
        byte[] result = basedata.clone();
        return result;
    }
    /**
     * @returns true if RUNWAY is filled with RUNWAY_MARKER
     **/
    public boolean isValid()
    {
        boolean result = true;
        for(int i= Field.RUNWAY.start(); i< Field.RUNWAY.end(); i++) {
            result = result && (RUNWAY_MARKER == basedata[i]);
        }
        return result;
    }
    public void close()
    {
        Arrays.fill(basedata,(byte)0);
    }

    /**
     * @param keyMaterial to make a copy to internal contents. Source is not used after constructor, and internal storage is cleared in close()
     * @param length the length of the target data this Metadata points to
     **/
    public Metadata(byte[] keyMaterial, long length)
    {
        if(keyMaterial.length != Field.KEY.length) {
            throw new IllegalArgumentException("Metadata key size is incorrect, was "+keyMaterial.length+" instead of "+Field.KEY.length);
        }
        ByteBuffer baseBuffer = ByteBuffer.wrap(basedata);
        for(int i = 0; i < Field.RUNWAY.length; i++) {
            baseBuffer.put(RUNWAY_MARKER);
        }
        baseBuffer.put(keyMaterial);
        baseBuffer.putLong(length);
    }
    public Metadata(byte[] copySource)
    {
        if(copySource.length != Field.size()) {
            throw new IllegalArgumentException("Metadata total size is incorrect, was "+copySource.length+ "instead of "+Field.size());
        }
        ByteBuffer.wrap(basedata).put(copySource);
    }
}
