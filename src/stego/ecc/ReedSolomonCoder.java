package stego.ecc;

import com.backblaze.erasure.*;
import java.util.concurrent.atomic.*;
import java.util.*;
import java.util.stream.*;


public class ReedSolomonCoder
    extends ArmorCoder
{
    public int armorFactor()
    {
	return 1+ (PARITY_SHARDS+datashards-1)/datashards;
    }
    public int maxData()
    {
	return datalength;
    }
    public int maxSourceData()
    {
	return shardsize * MAX_SHARDS;
    }
    public int minData()
    {
	return shardsize;
    }
    public ReedSolomonCoder(int datalength)
    {
	datashards = dataShards(datalength);
	shardsize = shardSize(datalength);
	this.datalength = datalength;
    }
    private final int datalength;
    private final int datashards;
    private final int shardsize;
    private static final int MAX_SHARDS = 256;
    private static final int PARITY_SHARDS = 128;
    public static int dataShards(int datalength)
    {
	return Math.min(datalength, MAX_SHARDS-PARITY_SHARDS);
    }
    public static int shardSize(int datalength)
    {
	final int datashards = dataShards(datalength);
	final int shardsize = (datalength + datashards -1)/datashards;
	return shardsize;
    }
    /**
     * Gets the total length of armored text after armoring chain
     *
     * @param datalength size of plaintext
     * @return size of armored text after chaining
     **/
    public int armoredLength(int datalength)
    {
	int packetSize = datashards*shardsize;
	int packets = datalength/packetSize;
	if(0<(datalength - packets*packetSize)) {
	    packets++;
	}
	int len = packets*(datashards+PARITY_SHARDS);
	//	int len = datalength;
	ArmorCoder next = getNext();
	if(null != next) {
	    len = next.armoredLength(len);
	}
	//len *= this.armorFactor();
	if(len < datalength)
	    throw new IllegalArgumentException("Overflow with length");
	return len;
    }
    public byte[][] encode(byte[] source)
    {
	if(source.length > datalength)
	    throw new IllegalArgumentException("Invalid source size: "+source.length
					       +", expected "+datalength);
	final int parityshards = PARITY_SHARDS; //TOTAL_SHARDS-shards;
	final int totalshards = datashards + parityshards;
	byte[][] shards = new byte[totalshards][shardsize];
	IntStream.range(0, datashards)
	    .parallel()
	    .forEach(i ->
		     {
			 if(i*shardsize < source.length) {
			     System
				 .arraycopy(source,i*shardsize,
					    shards[i],0,
					    Math.min(Math.max(0,source.length-i*shardsize), shardsize)
					    );
			 }
		     }
		     );
	ReedSolomon reedSolomon
	    = ReedSolomon.create(datashards, parityshards);
	reedSolomon.encodeParity(shards, 0, shardsize);
	return shards;
    }
    public DecodedPacket decode(DecodedPacket dps)
    {
	final int parityshards = PARITY_SHARDS;
	if((datashards+parityshards)*shardsize != dps.length()) {
	    throw new IllegalArgumentException("Expected data size of ("
					       +datashards+"+"+parityshards+")*"
					       +shardsize+"="+((datashards+parityshards)*shardsize)
					       +", got "+dps.length()+".");
	}
	AtomicInteger goodShards = new AtomicInteger();
	final boolean[] errors = dps.getErrors();
	float inErrors = IntStream.range(0,errors.length).parallel().filter(i -> errors[i]).count() / (1.0f*errors.length);
	final byte[] data = dps.getRawPacket();
	byte[][] shards = new byte[datashards+parityshards][shardsize];
	boolean[] present = new boolean[datashards+parityshards];
	IntStream.range(0, shards.length)
	    .parallel()
	    .forEach(i ->
		     {
			 int firstError = 0;
			 while((firstError < shardsize) && (!errors[i*shardsize+firstError])) {
			     firstError ++;
			 }
			 if(firstError < shardsize) {
			     present[i] = false;
			 } else {
			     present[i] = true;
			     System
				 .arraycopy(data, i*shardsize,
					    shards[i], 0,
					    shardsize
					    );
			     goodShards.getAndIncrement();
			 }
		     }
		     );
	if(goodShards.get() < datashards) {
	    System.err.println("too few good shards: "+goodShards.get());
	    boolean[] reserrors = new boolean[datalength];
	    Arrays.fill(reserrors, true);
	    return new DecodedPacket(new byte[datalength],reserrors,1.0f);
	}
	float shardErrors = ((datashards+parityshards -goodShards.get()) / (1.0f * (datashards+parityshards)));
	ReedSolomon reedSolomon = ReedSolomon.create(datashards, parityshards);
	reedSolomon.decodeMissing(shards, present, 0, shardsize);
	byte[] result = new byte[datalength];
	IntStream.range(0, datashards)
	    .parallel()
	    .forEach(i->
		     System.arraycopy(
				      shards[i], 0,
				      result, i*shardsize,
				      Math.min(shardsize, datalength-i*shardsize)
				      )
		     );
	return new DecodedPacket(result, new boolean[result.length], Math.max(inErrors, shardErrors));
    }
}
