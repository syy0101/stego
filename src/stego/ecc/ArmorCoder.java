package stego.ecc;

import java.util.*;
import java.util.stream.*;
import java.io.IOException;

/**
 * @author syy
 *
 * Abstract class to base armoring coders on and to chain them.
 **/

public abstract class ArmorCoder
{
    /**
     * Gets the block size of plaintext
     *
     * @return block size of plaintext for this armorer
     **/
    public abstract int maxData();

    /**
     * Gets the block size of armored text
     *
     * @return block size of armored text for this armorer
     **/
    protected abstract int maxSourceData();

    /**
     * Encode text to be armored with this armorer
     *
     * @param in plaintext to be armored
     * @return array of byte arrays that contain the armored packets
     **/
    protected abstract byte[][] encode(byte[] in);

    /**
     * Decode armored text with this armorer
     * 
     * @param in packet of armored text to decode
     * @return plaintext
     **/
    protected abstract DecodedPacket decode(DecodedPacket in);

    //next chained armorer
    private ArmorCoder next = null;
    protected ArmorCoder getNext()
    {
        return next;
    }

    /**
     * Gets the factor the armored text is larger than the plaintext
     *
     * @return the factor of armored text to plaintext
     **/
    protected abstract int armorFactor();

    /**
     * Gets the total length of armored text after armoring chain
     *
     * @param datalength size of plaintext
     * @return size of armored text after chaining
     **/
    public int armoredLength(int datalength)
    {
        int len = datalength;
        if(null != next) {
            len = next.armoredLength(datalength);
        }
        len *= this.armorFactor();
        if(len < datalength)
            throw new IllegalArgumentException("Overflow with length");
        return len;
    }

    /**
     * Gets the packet size that feeds a complete plaintext packet after chaining.
     *
     * @return the size of armored packet
     **/
    public int sourcePacketSize()
    {
        return armoredLength(maxData());
    }

    /**
     * Alters the state of this armoring by chaining the target armoring to happen after this armoring.
     *
     * @param n the armoring after this armoring
     * @return this armoring after chaining
     **/
    public ArmorCoder setNext(ArmorCoder n)
    {
        this.next = n;
        return this;
    }

    /**
     * Workhorse method of encoding the target packet and its children
     *
     * @param ep the EncodingPacket to encode
     **/
    private void encodeChain(EncodingPacket ep)
    {
        ep.split(this.maxData());

        //if this packet does not contain the actual data, then encode each child recursively
        if(!ep.isBottom()) {
            for(EncodingPacket cur : ep.getChildren()) {
                encodeChain(cur);
            }
        } else {
            //encoding main

            //encode the plaintext of this packet and store resulting packets into here
            byte[][] intermediate = this.encode(ep.getData());

            //gather resulting children here
            EncodingPacket[] result = new EncodingPacket[intermediate.length];
            Arrays
                .parallelSetAll(result,
                                i->
                                {
                                    //create the result packet
                                    EncodingPacket r = new EncodingPacket(intermediate[i]);

                                    //if we have a chained armorer, feed the result packets to them
                                    if(null != next) {

                                        int maxData = next.maxData();
                                        if(intermediate[i].length > maxData) {
                                            //if the current armored result is too large for the next armorer, split it
                                            byte[][] childData
                                                = new byte[maxData]
                                                [(intermediate[i].length +maxData-1)/maxData];
                                            EncodingPacket[] children
                                                = new EncodingPacket[childData.length];
                                            IntStream.range(0, childData.length)
                                                .parallel()
                                                .forEach(j ->
                                                         {
                                                             System
                                                                 .arraycopy(intermediate[i], j*maxData,
                                                                            childData[j], 0,
                                                                            Math
                                                                            .min(maxData,
                                                                                 intermediate[i].length
                                                                                 - j*maxData
                                                                                 )
                                                                            );
                                                             children[j] = new EncodingPacket(childData[j]);
                                                             next.encodeChain(children[j]);
                                                         }
                                                         );
                                            r.replaceData(children);
                                        } else {
                                            //if it was not too large, armor it by itself
                                            next.encodeChain(r);
                                        }
                                    }
                                    return r;                           
                                }
                                );
            //gather results to result
            ep.replaceData(result);
        }
    }

    /**
     * Encode the plaintext bytes into armored bytes through the whole chain
     *
     * @param in plaintext bytes
     * @return armored text bytes
     **/
    public byte[] encodeChain(byte[] in)
    {
        EncodingPacket top = new EncodingPacket(in);
        encodeChain(top);
        byte[] result =  top.flatten();
        top.destroy();
        return result;
    }

    /**
     * Decode armored text into plaintext through the whole chain
     *
     * @param in armored text packet
     * @return plain text packet
     **/
    public DecodedPacket decodeChain(DecodedPacket in)
    {
        DecodedPacket middle = in;

        //first unarmor the next armoring of the chain
        if(next != null) {

            //split the packet into correct sized packets for the chain's next armorer
            DecodedPacket[] packets = in.split(next.maxSourceData());

            //decode each packet
            IntStream.range(0,packets.length)
                .parallel()
                .forEach(i ->
                         packets[i] = next.decodeChain(packets[i])
                         );

            //join the resulted unarmored data into one again
            middle = DecodedPacket.join(packets);
        }

        //decode the armored data with this armoring

        //split the data into proper packets for this armorer
        DecodedPacket[] midpac = middle.split(this.maxSourceData());
        IntStream.range(0, midpac.length)
            .parallel()
            .forEach(i ->
                     {
                         midpac[i] = this.decode(midpac[i]);
                     }
                     );
        //join the plaintext results
        return DecodedPacket.join(midpac);
    }

    /**
     * Gets the default armoring chain: ReedSolomonCoder(128) chained to HammingCoder()
     *
     * @return ReedSolomonCoder(128) chained to HammingCoder()
     **/
    public static ArmorCoder getDefaultChain()
    {
        return
            new ReedSolomonCoder(128)
            .setNext(new HammingCoder());
    }

    /**
     * Main method for testing.
     *
     * @param args command line arguments
     * @throws IOException if such happens when io operating
     **/
    public static void main(String[] args)
        throws IOException
    {
        byte[] data =
            ("testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata"
            +"testdata")
            .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("testdata:");
        System.out.println(data.length);
        System.out.println(Arrays.toString(data));
        ArmorCoder def = ArmorCoder.getDefaultChain();
        byte[] encoded = def.encodeChain(data);
        System.out.println("encoded:");
        System.out.println(Arrays.toString(encoded));
        System.out.println("decodeorigin:");
        DecodedPacket decodeorigin = new DecodedPacket(encoded);
        System.out.println("decoderesult:");
        DecodedPacket decoderesult = def.decodeChain(decodeorigin);
        System.out.println("decoded:");
        System.out.println(Arrays.toString(decoderesult.split(data.length)[0].getRawPacket()));
        System.out.println("result: "+Arrays.equals(data, decoderesult.split(data.length)[0].getRawPacket()));
    }
}
