package stego.io;

import java.io.IOException;
import stego.crypto.FileSalt;

public interface LargeBitfield
{
    /**
     * Reads a bit in the address modulo size bits. 
     *
     * @param address target address
     * @return state of bit in address
     **/
    public boolean getBit(long address)
	throws IOException;

    /**
     * Writes a bit into target address. Blocks if the underlying ParallelByteBuffer blocks.
     *
     * @param address target address in bits
     * @param state if true, sets the bit, otherwise clears it
     **/
    public void setBit(long address, boolean state)
	throws IOException;

    /**
     * Gets the salt bytes on the tail.
     *
     * @return tail salt
     **/
    public FileSalt getFileSalt();
}
