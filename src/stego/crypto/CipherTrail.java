package stego.crypto;

import java.util.*;
import java.util.stream.*; 
import java.security.Security;
import java.security.SecureRandom;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
//import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import java.nio.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * @author syy 2022-06-26
 *
 **/

public class CipherTrail
{
    static
    {
        Security.addProvider(new BouncyCastleProvider());
        //Security.addProvider(new BouncyCastleFipsProvider());
    }

    public static final int AES256_BLOCK_SIZE_BYTES = 16;
    public static final int KEY_SIZE_BYTES = 32;
    public static final int KEY_SIZE_BITS = KEY_SIZE_BYTES*8;
    public static final int IV_SIZE_BYTES = AES256_BLOCK_SIZE_BYTES - Long.BYTES; // 8
    public static final int KEY_AND_IV_SIZE_BYTES = KEY_SIZE_BYTES + IV_SIZE_BYTES;
    public static final PasswordConverter ARGON2_CONVERTER = PasswordConverter.UTF8;

    public static final String SALT = "CipherTrailSaltString"; // Nothing in my sleeve -constant.
    private static final byte[] SALT_BYTES = ARGON2_CONVERTER.convert(SALT.toCharArray());

    public static final int PARALLELISM_LEVEL = 2;
    public static final int MEMORY_POW_TWO = 10;
    public static final int ITERATIONS = 2;
    public static final int ARGON2_VERSION = Argon2Parameters.ARGON2_VERSION_13;
    public static final int ARGON2_TYPE = Argon2Parameters.ARGON2_d;

    public static Argon2Parameters.Builder getNewParameterBuilder()
    {
        return
            new Argon2Parameters.Builder(ARGON2_TYPE)
            .withCharToByteConverter(ARGON2_CONVERTER)
            .withIterations(ITERATIONS)
            .withMemoryPowOfTwo(MEMORY_POW_TWO)
            .withParallelism(PARALLELISM_LEVEL)
            .withSalt(SALT_BYTES)
            .withVersion(ARGON2_VERSION);
    }

    private final Cipher addressCipher;
    private final Cipher contentCipher;
    private final byte[] addressBuffer = new byte[AES256_BLOCK_SIZE_BYTES];
    private final byte[] contentBuffer = new byte[AES256_BLOCK_SIZE_BYTES];
    private final LongBuffer addressLong = ByteBuffer.wrap(addressBuffer).position(IV_SIZE_BYTES).slice().asLongBuffer();
    private final LongBuffer contentLong = ByteBuffer.wrap(contentBuffer).position(IV_SIZE_BYTES).slice().asLongBuffer();    
    
    public CipherHop findHop(long bitAddress)
    {
        byte[] resultBuf;
        try {

            long addressCounterBlockAddress = bitAddress / ( AES256_BLOCK_SIZE_BYTES / Long.BYTES);
            int addressCounterBlockNumber = Math.toIntExact(Math.floorMod(bitAddress, ( AES256_BLOCK_SIZE_BYTES / Long.BYTES)));
            addressLong.put(0,addressCounterBlockAddress);
            resultBuf = addressCipher.doFinal(addressBuffer);
            long hopAddress = ByteBuffer.wrap(resultBuf).asLongBuffer().get(addressCounterBlockNumber);
            Arrays.fill(resultBuf,(byte)0);

            long contentBlockAddress = bitAddress / (8*AES256_BLOCK_SIZE_BYTES);
            int bitPositionInContentBlock = Math.toIntExact(Math.floorMod(bitAddress, (8*AES256_BLOCK_SIZE_BYTES)));
            int bytePositionInContentBlock = bitPositionInContentBlock / 8;
            int bitPositionInByte = Math.floorMod(bitPositionInContentBlock, 8);
            byte bitMask = (byte)(1 << bitPositionInByte);

            contentLong.put(0,contentBlockAddress);
            resultBuf = contentCipher.doFinal(contentBuffer);
            boolean hopCipherBit =
                (0 != (resultBuf[bytePositionInContentBlock] & bitMask));
            Arrays.fill(resultBuf,(byte)0);

            return new CipherHop(hopAddress, hopCipherBit);
        }
        catch(IllegalBlockSizeException ibse) {
            throw new IllegalStateException(ibse);
        }
        catch(BadPaddingException bpe) {
            throw new IllegalStateException(bpe);
        }
    }
    public List<CipherHop> findBlocksHops(long firstBitAddress)
    {
        /*
        long offset = firstBitAddress % (8*AES256_BLOCK_SIZE_BYTES);
        if(0 != offset) {
            throw IllegalArgumentException("Trying to find block's Hops from other point than start of block: "+firstBitAddress+" offset is "+offset);
        }
        */
        byte[] contentResultBuf = new byte[AES256_BLOCK_SIZE_BYTES];
        byte[] addressResultBuf = new byte[Long.BYTES * contentResultBuf.length * 8];
        ArrayList<CipherHop> result = null;
        try {

            long contentBlockAddress = firstBitAddress / (8*AES256_BLOCK_SIZE_BYTES);
            long contentBlockFirstBitAddress = contentBlockAddress * (8*AES256_BLOCK_SIZE_BYTES);
            int contentFirstBitOffset = Math.toIntExact(firstBitAddress - contentBlockFirstBitAddress);

            contentLong.put(0,contentBlockAddress);
            contentResultBuf = contentCipher.doFinal(contentBuffer);

            long addressBlockStartAddress = firstBitAddress / ( AES256_BLOCK_SIZE_BYTES / Long.BYTES);
            long addressBlockFirstBitAddress = addressBlockStartAddress * ( AES256_BLOCK_SIZE_BYTES / Long.BYTES);
            int addressFirstBitOffset = Math.toIntExact(firstBitAddress - addressBlockFirstBitAddress); // - addressBlockStartAddress);
            for(int currentStart = 0; currentStart < addressResultBuf.length; currentStart += AES256_BLOCK_SIZE_BYTES) {
                addressLong.put(0,addressBlockStartAddress);
                addressCipher.doFinal(addressBuffer,0,AES256_BLOCK_SIZE_BYTES,addressResultBuf,currentStart);
                addressBlockStartAddress++;
            }
            LongBuffer resultAddresses = ByteBuffer.wrap(addressResultBuf).asLongBuffer().position(addressFirstBitOffset);
            result = new ArrayList<CipherHop>(contentResultBuf.length * 8 - contentFirstBitOffset);
            for(int i = contentFirstBitOffset; i< contentResultBuf.length * 8; i++) {
                int targetByte = i / 8;
                int targetBit = Math.floorMod(i, 8);
                byte targetBitMask = (byte)(1 << targetBit);
                boolean resultBit
                    = (0 != (contentResultBuf[targetByte] & targetBitMask));
                result.add(new CipherHop(resultAddresses.get(), resultBit));
            }
        }
        catch(ShortBufferException sbe) {
            throw new IllegalStateException(sbe);
        }
        catch(IllegalBlockSizeException ibse) {
            throw new IllegalStateException(ibse);
        }
        catch(BadPaddingException bpe) {
            throw new IllegalStateException(bpe);
        }
        finally {
            Arrays.fill(contentResultBuf, (byte)0);
            Arrays.fill(addressResultBuf, (byte)0);
        }
        return result;
    }
    private static byte[] getRandomBytes(int byteAmount)
    {
        byte[] result = new byte[byteAmount];
        new SecureRandom().nextBytes(result);
        return result;
    }
    public CipherTrail(char[] password, int passwordNonceSizeInBytes)
    {
        this(password, getRandomBytes(passwordNonceSizeInBytes), true);
    }
    public CipherTrail(char[] password, byte[] nonce)
    {
        this(password, nonce, false);
    }
    public CipherTrail(char[] password, byte[] nonce, boolean cleanNonceAfterUse)
    {
        this(true, createKeyIvMaterial(password, nonce, cleanNonceAfterUse));
    }
    private static byte[] createKeyIvMaterial(char[] password, byte[] nonce, boolean cleanNonceAfterUse)
    {
        Argon2BytesGenerator keyGenerator = new Argon2BytesGenerator();
        keyGenerator.init(getNewParameterBuilder().withSecret(nonce).build());
        if(cleanNonceAfterUse) {
            Arrays.fill(nonce, (byte)0);
        }
        
        byte[] keyIvMaterial = new byte[2*KEY_AND_IV_SIZE_BYTES];
        keyGenerator.generateBytes(password, keyIvMaterial);
        return keyIvMaterial;
    }

    public CipherTrail(byte[] key)
    {
        this(true,createKeyIvMaterial(key));
    }
    private static byte[] createKeyIvMaterial(byte[] key)
    {
        Argon2BytesGenerator keyGenerator = new Argon2BytesGenerator();
        keyGenerator.init(getNewParameterBuilder().build());
        
        byte[] keyIvMaterial = new byte[2*KEY_AND_IV_SIZE_BYTES];
        keyGenerator.generateBytes(key, keyIvMaterial);
        return keyIvMaterial;
    }

    private CipherTrail(boolean internal, byte[] keyIvMaterial)
    {
        try {
            SecretKeySpec addressKey = new SecretKeySpec(keyIvMaterial, 0, KEY_SIZE_BYTES, "AES");
            System.arraycopy(keyIvMaterial, KEY_SIZE_BYTES, addressBuffer, 0, IV_SIZE_BYTES);
            SecretKeySpec contentKey = new SecretKeySpec(keyIvMaterial, KEY_SIZE_BYTES + IV_SIZE_BYTES, KEY_SIZE_BYTES, "AES");
            System.arraycopy(keyIvMaterial, KEY_SIZE_BYTES+IV_SIZE_BYTES+KEY_SIZE_BYTES, contentBuffer, 0, IV_SIZE_BYTES);

            //  addressCipher = Cipher.getInstance("AES/CTR/NoPadding", "BCFIPS");
            addressCipher = Cipher.getInstance("AES_256/ECB/NoPadding");
            addressCipher.init(Cipher.ENCRYPT_MODE, addressKey);
        
            //contentCipher = Cipher.getInstance("AES/CTR/NoPadding", "BCFIPS");
            contentCipher = Cipher.getInstance("AES_256/ECB/NoPadding");
            contentCipher.init(Cipher.ENCRYPT_MODE, contentKey);
        }
        catch(InvalidKeyException ike) {
            throw new IllegalStateException(ike);
        }
        catch(NoSuchAlgorithmException nsae) {
            throw new IllegalStateException(nsae);
        }
        catch(NoSuchPaddingException nspe) {
            throw new IllegalStateException(nspe);
        }
        //      catch(NoSuchProviderException nspre) {
        //    throw new IllegalStateException(nspre);
        //}
    }
}
