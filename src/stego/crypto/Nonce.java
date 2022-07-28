package stego.crypto;

import java.util.Arrays;
import java.security.SecureRandom;

public class Nonce extends GuardedByteArray
{
    public Nonce(byte[] source)
    {
	super(source);
    }
    public Nonce(SecureRandom random, int minimumNonceSize)
    {
	super(new byte[getNonceSizeBytes(minimumNonceSize, random)]);
	random.nextBytes(this.bytes);
    }
    /**
     * Gives a random number which is the count of continuous trues from SecureRandom
     *
     * @param minimumNonceSizeBytes base minimum nonce size
     * @param random the SecureRandom which bits are got from
     * @returns minimumNonceSizeBytes + count of continuous 1s/trues from random
     **/
    public static int getNonceSizeBytes(int minimumNonceSizeBytes, SecureRandom random)
    {
	int result = 0;
	while(random.nextBoolean()) {
	    result++;
	}
	result /= 4;
	return result+minimumNonceSizeBytes;
    }
    public boolean incrementAndCheck(GuardedByteArray target)
    {
	byte[] current = this.bytes;
	if(current.length != target.bytes.length) {
	    throw new IllegalArgumentException
		("current and target array length mismatch: "
		 +current.length+" != "+target.bytes.length);
	}
	boolean incremented = false;
	int currentByte = 0;
	while((!incremented) && (currentByte<current.length)) {
	    current[currentByte]++;
	    if(current[currentByte] != target.bytes[currentByte]) {
		incremented = true;
	    } else {
		currentByte++;
	    }
	}
	return incremented;
    }
}
