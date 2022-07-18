package stego.io;

import java.io.*;
import java.util.*;
import java.util.stream.IntStream;
import java.security.SecureRandom;

/**
 * @author syy 2022-06-25
 *
 * Class to read and write parallel into a File.
 **/


public class RandomAccessBitFile implements LargeBitfield, AutoCloseable
{
    public final byte LOW_BIT_MASK = (byte)0x7;
    
    private final File targetFile;
    private final long fileLength;
    private LockMap<Long> byteLockMap = new LockMap<Long>();
    private boolean isClosed = false;
    private Set<RandomAccessFile> openFiles = Collections.synchronizedSet(new HashSet<RandomAccessFile>());

    /**
     * Checks if this RandomAccessBitFile is closed and throws IOException if it is
     *
     * @throws IOException if this file is already closed.
     **/
    private void throwIfClosed()
        throws IOException
    {
        if(isClosed) {
            throw new IOException("Access to RandomAccessFile after it is closed.");
        }
    }

    /**
     * Opens a new RandomAccessFile to the target File for a Thread to read and write on and attaches it to list of open files to be automatically closed on close().
     *
     * @returns the new RandomAccessFile or null if this RandomAccessBitFile has already been closed.
     **/
    private synchronized RandomAccessFile createRandomAccessFile()
    {
        if(isClosed) return null;
        try {
        RandomAccessFile raf = new RandomAccessFile(targetFile, "rws");
        openFiles.add(raf);
        return raf;
        }
        catch(IOException ioe) {
            return null;
        }
    }

    private ThreadLocal<RandomAccessFile> threadLocalFile = ThreadLocal.withInitial(() -> createRandomAccessFile());

    /**
     * Constructs a new RandomAccessBitFile to read and write parallel on target File.
     *
     * @returns new RandomAccessBitFile
     **/
    public RandomAccessBitFile(File raf)
    {
        this.targetFile = raf;
        this.fileLength = targetFile.length();
    }

    public static void createNewBitFile(File raf, long size)
        throws IOException
    {
        createNewBitFile(raf, size, new SecureRandom());
    }
    
    public static void createNewBitFile(File raf, long size, SecureRandom random)
        throws IOException
    {
        final int BUFSIZE = 1024*1024;
        byte[] randbuf = new byte[BUFSIZE];
        try(FileOutputStream fos = new FileOutputStream(raf)) {
            while(size > 0) {
                random.nextBytes(randbuf);
                fos.write(randbuf, 0, Math.toIntExact(Math.min(BUFSIZE, size)));
                size -= BUFSIZE;
            }
        }
        finally {
            Arrays.fill(randbuf, (byte)0);
        }
    }

    /**
     * Closes this RandomAccessBitFile and all of its RandomAccessFiles that are used to read and write the target File.
     *
     * @throws IOException if closing one of the RandomAccessFiles throws IOException.
     **/
    public synchronized void close()
        throws IOException
    {
        if(isClosed) return;
        isClosed = true;
        Optional<Exception> oe =
            openFiles.stream()
            .map(f -> {
                    try {
                        f.close();
                    }
                    catch(Exception e) {
                        return e;
                    }
                    return null;
                })
            .filter(e -> null != e)
            .findAny();
        if(oe.isPresent()) {
            throw new IOException(oe.get());
        }           
        openFiles.clear();
    }
    
    /**
     * Reads a bit in the address modulo size bits. 
     *
     * @param address target address
     * @return state of bit in address
     **/
    public boolean getBit(long address)
        throws IOException
    {
        long byteAddress = Math.floorMod((address / 8), fileLength);
        try(LockMap.Lock myLock = byteLockMap.lock(byteAddress)) {
            RandomAccessFile raf = threadLocalFile.get();
            byte bitAddress = (byte)(LOW_BIT_MASK & address);
            byte bitMask = (byte)(1 << bitAddress);
            raf.seek(byteAddress);
            boolean result = 0 != (raf.readByte() & bitMask);
            return result;
        }
    }

    /**
     * Writes a bit into target address. Blocks if the underlying ParallelByteBuffer blocks.
     *
     * @param address target address in bits
     * @param state if true, sets the bit, otherwise clears it
     **/
    public synchronized void setBit(long address, boolean state)
        throws IOException
    {
        long byteAddress = Math.floorMod((address / 8), fileLength);
        try(LockMap.Lock myLock = byteLockMap.lock(byteAddress)) {
            RandomAccessFile raf = threadLocalFile.get();
            byte bitAddress = (byte)(LOW_BIT_MASK & address);
            byte bitMaskOn = (byte)(1 << bitAddress);
            byte bitMaskOff = (byte)(255 - bitMaskOn);
            raf.seek(byteAddress);
            byte currentByte = raf.readByte();
            if(state) {
                currentByte |= bitMaskOn;
            } else {
                currentByte &= bitMaskOff;
            }
            raf.seek(byteAddress);
            raf.writeByte(currentByte);
        }
    }

    /**
     * Testing methods
     **/

    private static void initializeTestFile(File f, long size)
        throws IOException
    {
        try(BufferedOutputStream bw = new BufferedOutputStream(new FileOutputStream(f))) {
            for(long l = 0; l<size;l++) {
                bw.write(0);
            }
        }
    }

    private static long addressTransformation(int i)
    {
        return
            ((long)i)*i*i+((long)i)*i+i;
    }
    private static boolean RandomAccessWriteTest(File f)
    {
        final long fileLength = f.length();
        try (RandomAccessBitFile bitFile
             = new RandomAccessBitFile(f)) {
            Optional<IOException> oioe =
                IntStream.range(0,100000).parallel()
                .peek(i -> {
                        if(0 == i%100) {
                            System.out.print(".");
                        }
                    })
                .mapToObj(i -> {
                        try {
                            bitFile.setBit(addressTransformation(i), 0 != Long.bitCount(addressTransformation(i)%fileLength)%2);
                            return null;
                        } catch (IOException ioe) {
                            return ioe;
                        }
                    })
                .filter(e -> null != e)
                .findAny();
            if(oioe.isPresent()) {
                oioe.get().printStackTrace();
                return false;
            }
        }
        catch (IOException closeException) {
            closeException.printStackTrace();
            return false;
        }
        return true;
    }

    private static boolean RandomAccessReadTest(File f)
    {
        final long fileLength = f.length();
        boolean result = true;
        try (RandomAccessBitFile bitFile = new RandomAccessBitFile(f)) {
            result =
                IntStream.range(0,100000).parallel()
                .peek(i -> {
                        if(0 == i%100) {
                            System.out.print(".");
                        }
                    })
                .filter(i -> {
                        try {
                            boolean bit = bitFile.getBit(addressTransformation(i));
                            if(bit && bit != (0 != Long.bitCount(addressTransformation(i)%fileLength)%2)) {
                                System.out.println("at "+i+" there should have been "+Long.bitCount(addressTransformation(i)%fileLength)%2+" but there was "+(bit ? 1:0));
                                return true; // found error
                            }
                            return false; // no error
                        }
                        catch (IOException ioe) {
                            ioe.printStackTrace();
                            return true;
                        }
                    })
                .findAny().isPresent();
            result = !result;
        }
        catch(IOException ioe) {
            ioe.printStackTrace();
            return false;
        }
        return result;
    }

    public static void main(String[] args)
        throws IOException
    {
        String testFileName = "test.tmp";
        long testFileLength = 10000l;
        for(String arg : args) {
            try {
                testFileLength = Long.valueOf(arg);
            }
            catch(NumberFormatException nfe) {
                testFileName = arg;
            }
        }
        File testFile = new File(testFileName);
        System.out.println("Testfile: '"+testFileName+"' "+testFileLength+" bytes.");
        initializeTestFile(testFile, testFileLength);
        
        int trials = 0;
        int successes = 0;

        trials++;
        if(RandomAccessWriteTest(testFile)) {
            System.out.println("Test file write passed.");
            successes++;
        }

        trials++;
        if(RandomAccessReadTest(testFile)) {
            System.out.println("Test file read passed.");
            successes++;
        }

        System.out.println(""+successes+"/"+trials+" tests succeeded.");
    }
}
