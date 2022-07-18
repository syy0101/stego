package stego.crypto;

public class CipherHop
{
    public final long address;
    public final boolean cipherBit;
    public CipherHop(long address, boolean cipherBit)
    {
        this.address = address;
        this.cipherBit = cipherBit;
    }
}
