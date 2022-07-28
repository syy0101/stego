package stego.ecc;

//import java.nio.ByteBuffer;
import java.util.stream.*;
import java.util.Arrays;
import javax.security.auth.Destroyable;
import stego.DestroyableCloseable;

public class DecodedPacket
    implements DestroyableCloseable
{
    private final float dataErrors;
    private byte[] packet;
    private boolean[] errors;
    public float getDataErrors()
    {
	return dataErrors;
    }
    public DecodedPacket(byte[] packet)
    {
	this(packet,new boolean[packet.length],0.0f);
    }
    public DecodedPacket(byte[] packet, boolean[] errors, float dataErrors)
    {
	if(packet.length != errors.length) {
	    throw new IllegalArgumentException("Mismatched packet and error size: "
					       +packet.length+", "+errors.length);
	}
	this.dataErrors = dataErrors;
	this.packet = packet;
	this.errors = errors;
    }
    @Override
    public void destroy()
    {
	Arrays.fill(packet, (byte)0);
	Arrays.fill(errors, false);
	packet = null;
	errors = null;
	destroyed = true;
    }
    @Override
    public boolean isDestroyed()
    {
	return destroyed;
    }
    private boolean destroyed = false;
    public DecodedPacket[] split(int size)
    {
	if(size >= packet.length)
	    return new DecodedPacket[] {this};
	int amount = (packet.length + size -1 )/size;
	DecodedPacket[] result = new DecodedPacket[amount];
	IntStream.range(0, amount)
	    .parallel()
	    .forEach(i ->
		     {
			 int pSize = Math.min(size, packet.length - i*size);
			 byte[] pPacket = new byte[pSize];
			 boolean[] pErrors = new boolean[pSize];
			 System
			     .arraycopy(packet,i*size,
					pPacket,0,
					pPacket.length);
			 System
			     .arraycopy(errors,i*size,
					pErrors,0,
					pErrors.length);
			 result[i] = new DecodedPacket(pPacket, pErrors,dataErrors);
		     }
		     );
	destroy();
	return result;
    }
    public static DecodedPacket join(DecodedPacket... in)
    {
	int[] cumulativeSize = new int[in.length];
	float dErrors = 0.0f;
	for(int i = 0; i< in.length;i++) {
	    cumulativeSize[i] = in[i].length() + ((i >0)?cumulativeSize[i-1] : 0);
	    dErrors = (dErrors*((i>0)?cumulativeSize[i-1]:0) + in[i].dataErrors*in[i].errors.length)/cumulativeSize[i];
	}
	byte[] totalPacket = new byte[cumulativeSize[in.length-1]];
	boolean[] totalErrors = new boolean[totalPacket.length];
	IntStream.range(0,in.length)
	    //.parallel()
	    .forEach(i ->
		     {
			 int start = ((i>0)
				      ?cumulativeSize[i-1]
				      :0
				      );
			 System
			     .arraycopy(in[i].packet, 0,
					totalPacket, start,
					in[i].packet.length
					);
			 System.arraycopy(in[i].errors, 0,
					  totalErrors, start,
					  in[i].errors.length
					  );
		     }
		     );
	for(DecodedPacket dp : in)
	    dp.destroy();
	return new DecodedPacket(totalPacket, totalErrors,dErrors);
    }
    public int length()
    {
	return errors.length;
    }
    public byte[] getRawPacket()
    {
	return packet.clone();
    }
    public boolean[] getErrors()
    {
	return errors.clone();
    }
    public byte[] getNonErrored()
    {
	byte[] temp = new byte[packet.length];
	int t = 0;
	for(int i = 0; i<packet.length;i++) {
	    if(!errors[i]) {
		temp[t] = packet[i];
		t++;
	    }
	}
	byte[] result = new byte[t];
	System.arraycopy(temp,0,result, 0, t);
	return result;
    }
}
