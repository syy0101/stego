package stego.ecc;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.stream.IntStream;
import java.util.concurrent.atomic.AtomicInteger;

public class HammingCoder
    extends ArmorCoder
{
    public int armorFactor()
    {
	return 2;
    }
    private AtomicInteger errorCount = new AtomicInteger();
    public int getErrorCount()
    {
	return errorCount.get();
    }
    public void clearErrorCount()
    {
	errorCount.set(0);
    }
    
    public int maxData()
    {
	return Integer.MAX_VALUE / 2;
    }
    public int maxSourceData()
    {
	return Integer.MAX_VALUE;
    }
    public byte[][] encode(byte[] in)
    {
	int limit = in.length;
	int size = (limit +1)/2;
	byte[][] result = new byte[2][];
	result[0] = new byte[size*2];
	result[1] = new byte[limit*2-size*2];
	IntStream.range(0, limit)
	    .parallel()
	    .forEach(i ->
		     {
			 int e = encode((int)(0xff&in[i]));
			 int h = (i<size*2)? 0:1;
			 int j = (h==0)? i*2: i*2-size*2;
			 result[h][j] = (byte)(e & 0xff);
			 result[h][j+1] = (byte)((e >>> 8) & 0xff);
		     }
		     );
	return result;
    }

    public DecodedPacket decode(DecodedPacket in)
    {
	if(in.length()% 2 != 0)
	    throw new IllegalArgumentException();
	byte[] data = in.getRawPacket();
	int datasize = data.length /2;
	DecodedPacket intermediate = decodeBytesMarkErrors(data);
	boolean[] inerrors = in.getErrors();
	boolean[] errors = intermediate.getErrors();
	IntStream.range(0, datasize)
	    .parallel()
	    .forEach(i ->
		     errors[i]
		     = errors[i]
		     || inerrors[i*2]
		     || inerrors[i*2+1]
		     );
	float dErrors = IntStream.range(0,errors.length).parallel().filter(i -> errors[i]).count() / (1.0f*errors.length);
	return new DecodedPacket(intermediate.getRawPacket(), errors, dErrors);
    }
    public DecodedPacket decodeBytesMarkErrors(byte[] in)
    {
	int limit = in.length/2;
	byte[] result = new byte[limit];
	boolean[] errors = new boolean[result.length];
	IntStream.range(0, limit)
	    .parallel()
	    .forEach(i ->
		     {
			 try {
			     result[i]
				 = (byte)(decode(0xffff
						 &(
						   (0xff00&(in[i*2+1] << 8))
						   | (0xff&in[i*2])
						   )
						 ,this)
					  );
			 }
			 catch(CodingException ce) {
			     result[i] = (byte)0;
			     errors[i] = true;
			 }
		     }
		     );
	float dErrors = IntStream.range(0,errors.length).parallel().filter(i -> errors[i]).count() / (1.0f*errors.length);
	return new DecodedPacket(result, errors,dErrors);		     
    }
    
    public static int encodeHalf(int in)
    {
	in &= 0xf;
	//int right = in & 0xf;
	int d1 = in & 1;
	in >>>= 1;
	int d2 = in & 1;
	in >>>= 1;
	int d3 = in & 1;
	in >>>= 1;
	int d4 = in & 1;
	int p1 = d1 ^ d2 ^ d4;
	int p2 = d1 ^ d3 ^ d4;
	int p3 = d2 ^ d3 ^ d4;
	int p4 = d1 ^ d2 ^ d3 ^ d4 ^ p1 ^ p2 ^ p3;
	//int p4 = d3 ^ d1 ^ d2;
	return
	    ((((((((((((((p4 << 1)
			 | d4) <<1)
		       | d3) <<1)
		     | d2) <<1)
		   | p3) <<1)
		 | d1) <<1)
	       | p2) <<1)
	     | p1);	
    }

    public static int encode(int in)
    {
	return
	    encodeHalf(in & 0xf) | (encodeHalf((in >>> 4) & 0xf) << 8);
    }

    public static int encode2(int in)
    {
	return
	    encode(in & 0xff) | (encode((in >>> 8) & 0xff) << 16);
    }

    public int decode(int input)
	throws CodingException
    {
	return decode(input, this);
    }
    
    public int decodeHalf(int input)
	throws CodingException
    {
	return decodeHalf(input, this);
    }
    public static int decodeHalf(int input, HammingCoder state)
	throws CodingException
    {
	int in = input & 0xff;
	int parityerror = Integer.bitCount(in & 0x7f) & 1;
	int p1 = in & 1;
	in >>>= 1;
	int p2 = in & 1;
	in >>>= 1;
	int d1 = in & 1;
	in >>>= 1;
	int p3 = in & 1;
	in >>>= 1;
	int d2 = in & 1;
	in >>>= 1;
	int d3 = in & 1;
	in >>>= 1;
	int d4 = in & 1;
	in >>>= 1;
	int p4 = in & 1;
	int error
	    = ((((p3 ^ d2 ^d3 ^ d4) <<1) | (p2 ^d1 ^d3 ^d4)) << 1) | (p1 ^d1 ^ d2 ^ d4);
	if(p4 != parityerror) {
	    if(null != state) state.errorCount.getAndIncrement();
	    if(error != 0) {
		input ^= (1 << (error-1));
	    }	    
	} else {
	    if(error != 0) {
		if(null != state) state.errorCount.getAndIncrement();
		throw new CodingException();
	    }		
	}
	return
	    ((input >>>2) & 1) | ((input >>>3) & 0xe);
    }

    public static int decode(int input, HammingCoder state)
	throws CodingException
    {
	return decodeHalf(input & 0xff, state) | (decodeHalf((input >>> 8) & 0xff, state) << 4);
    }

    public int decode2(int input)
	throws CodingException
    {
	return decode2(input, this);
    }
    public static int decode2(int input, HammingCoder state)
	throws CodingException
    {
	return decode(input & 0xffff, state) | (decode((input >>> 16) & 0xffff, state) << 8);
    }

}
