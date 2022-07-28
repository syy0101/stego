package stego.ecc;

import stego.DestroyableCloseable;
import java.util.*;
import java.util.stream.*;
import java.nio.*;
import javax.security.auth.Destroyable;

/**
 * @author syy 2018-12-22 - 2019-01-01
 *
 * Implements DestryableCloseable in order to allow automatic
 * destroying of contents after use.
 **/

public class EncodingPacket
    implements DestroyableCloseable
{
    private boolean destroyed = false;

    /**
     * Destroys data contained in this.
     * Clears the binary data in this and all of this children.
     * Calls destroy on all this children.
     **/
    public void destroy()
    {
	if(child != null) {
	    destroyChildren();
	}
	clearData();
	destroyed = true;
	
    }

    /**
     * Returns if this is destroyed.
     *
     * @return true if destroy() has been called for this, otherwise false
     **/
    public boolean isDestroyed()
    {
	return destroyed;
    }

    /**
     * Calls destroy on all this children.
     **/
    private void destroyChildren()
    {
	if(null == child)
	    return;
	for(EncodingPacket ep : child)
	    ep.destroy();
	child = null;
    }

    /**
     * Clears the binary data on this.
     **/
    private void clearData()
    {
	if(data != null) {
	    Arrays.fill(data, (byte) 0);
	    data = null;
	}
    }

    //children of this
    private EncodingPacket[] child = null;

    //data of this
    private byte[] data = null;

    /**
     * Creates EncodingPackets to wrap byte[] in source
     *
     * @param source the source data
     * @return EncodingPackets that wrap the source data
     **/
    public static EncodingPacket[] wrap(byte[][] source)
    {
	EncodingPacket[] result = new EncodingPacket[source.length];
	Arrays.parallelSetAll(result,
			      i -> new EncodingPacket(source[i])
			      );
	return result;
    }

    /**
     * Splits the binary data of this to child EncodedPackets with given size.
     *
     * @param size the target size in bytes
     *
     * @throws IllegalStateException if destroy() has been called.
     **/
    public void split(int size)
    {
	if(destroyed)
	    throw new IllegalStateException();

	//if this does not contain data in itself, do nothing
	if(!isBottom()) {
	    return;
	}

	//if we don't have data but for 1 packet, do nothing
	if(data.length <= size)
	    return;

	//calculate how many packets we need
	int amount = (data.length + size -1) / size;
	byte[][] nData = new byte[amount][];
	IntStream.range(0, amount)
	    .parallel()
	    .forEach(i ->
		     {
			 //allocate the amount of bytes that go into the child packet
			 nData[i]
			     = new byte[Math
					.min(size,
					     data.length - i*size
					     )
					];
			 //copy the correct amount of bytes from this data to child data packet
			 System
			     .arraycopy(data, i*size,
					nData[i],0,
					nData[i].length
					);
		     }
		     );
	//switch this packet to contain the child packets instead of data.
	replaceData(wrap(nData));
    }

    /**
     * Gets all data of this or its children or their children etc
     * as one continuous byte[]
     *
     * @return the data in order from first child to last
     * @throws IllegalStateException if destroy() has been called
     **/
    public byte[] flatten()
    {
	if(destroyed)
	    throw new IllegalStateException();

	//make a list of all packets in the tree of this and children
	int index = 0;
	ArrayList<EncodingPacket> bottomPackets = new ArrayList<EncodingPacket>();

	//add this itself for checking
	bottomPackets.add(this);

	//repeat loop to finding bottom packets with data
	while(index < bottomPackets.size()) {

	    //all the packets before current index are bottom packets
	    EncodingPacket current = bottomPackets.get(index);
	    if(current.isBottom()) {
		//if current is a bottom packet, move on
		index++;
	    } else {
		//if this was not a bottom packet, replace this packet with its child packets
		//retain the index so the next time we check the first child
		bottomPackets.remove(index);
		bottomPackets.addAll(index, Arrays.asList(current.getChildren()));
	    }
	}
	//now the bottomPackets contain the bottom packets in order
	
	//make temporary space to store copies of the data of bottom packets
	byte[][] result = new byte[bottomPackets.size()][];

	//array to calculate the starting positions of datas
	int[] cumSize = new int[result.length];

	//copy the datas into the temporary space
	//and calculate the cumulative ending points of each data
	for(int i = 0; i< result.length; i++) {
	    result[i] = bottomPackets.get(i).getData();
	    cumSize[i] = result[i].length + ((i>0)?cumSize[i-1]:0);
	}

	//array for the result
	byte[] res = new byte[cumSize[cumSize.length-1]];

	IntStream.range(0, result.length)
	    .parallel()
	    .forEach(i->
		     {
			 //copy the temp datas to result
			 System.arraycopy(result[i],0,
					  res, ((i>0)? cumSize[i-1] : 0),
					  result[i].length
					  );
			 //clear the temp data after copy
			 Arrays.fill(result[i],(byte)0);
		     }
		     );

	//return result
	return res;
    }

    /**
     * Grabs the source data into new EncodingPacket and clears the source data.
     *
     * @param source the source data
//     * @return new EncodingPacket holding the source data
     **/
    public EncodingPacket(byte[] source)
    {
	data = source.clone();
	Arrays.fill(source, (byte)0);
    }

    /**
     * Wraps the source packets as children of the new packet.
     *
     * @param children the child packets
//     * @return new EncodingPacket holding the child packets
     **/
    public EncodingPacket(EncodingPacket[] children)
    {
	child = children.clone();
    }

    /**
     * Checks if this packet contains directly data.
     *
     * @return true if this packet contains data directly
     **/
    public boolean isBottom()
    {
	return data != null;
    }

    /**
     * Gets the data in this packet. Clears the data from this packet.
     *
     * @return the data in this packet.
     **/
    public byte[] getData()
    {
	byte[] result = data.clone();
	clearData();
	return result;
    }

    /**
     * Gets the children of this packet.
     *
     * @return the children of this packet.
     **/
    public EncodingPacket[] getChildren()
    {
	return child.clone();
    }

    /**
     * Replaces the contents of this packet with the given children.
     *
     * @param children the new children content of this packet
     * @throws IllegalStateException if destroy() has been called
     **/
    public void replaceData(EncodingPacket[] children)
    {
	clearData();
	destroyChildren();
	if(destroyed)
	    throw new IllegalStateException();
	child = children.clone();
    }

    /**
     * Replaces the contents of this packet with the given data.
     *
     * @param data new data to hold in this packet
     * @throws IllegalStateException if destroy() has been called
     **/
    public void replaceData(byte[] data)
    {
	destroyChildren();
	clearData();
	if(destroyed)
	    throw new IllegalStateException();
	this.data = data.clone();
	Arrays.fill(data, (byte)0);
    }
}
