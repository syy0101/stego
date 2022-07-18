package stego.util;

import java.io.*;
import java.util.*;
import java.util.stream.Collectors;
import stego.io.*;

/**
 * Command line interface for stegodata.
 *
 * @author syy 2022-07-17
 **/

public class CommandLineInterface
{
    /**
     * Marker for std pipe streams.
     **/
    public static final String PIPENAME = "-";
    
    /**
     * Default buffer size in bytes for piping.
     **/
    public static final int BUFSIZE = 1024*1024;

    /**
     * Command flags for the interface.
     **/
    public enum COMMAND
    {
        /**
         * creates new bitfile
         **/
        CREATE("-c"),
        /**
         * reads stegodata from bitfile
         **/
        READ("-r"),
        /**
         * writes stegodata to bitfile
         **/
        WRITE("-w"),
        /**
         * changes current nonce size
         **/
        NONCE("-n");

        /**
         * Contains the command string of this command.
         **/
        public final String text;
        private COMMAND(String comm)
        {
            this.text = comm;
        }

        /**
         * Parses COMMAND from Strign
         *
         * @param str the String to parse COMMAND from.
         * @returns COMMAND the str contained or null if no COMMAND found.
         **/
        public static COMMAND parse(String str)
        {
            for(COMMAND current : values()) {
                if(current.text.equals(str)) {
                    return current;
                }
            }
            return null;
        }
    }

      public enum SI
    {
        K,
        M,
        G,
        T,
        P;
        private SI()
        {
        }
        public final static long BASE = 1000;
        public long getFactor()
        {
            long result = BASE;
            for(int i=0; i<this.ordinal();i++) {
                result *= BASE;
            }
            return result;
        }
        public static SI parse(String s)
        {
            if(null != s) {
                for(SI current : values()) {
                    if(current.name().toUpperCase().equals(s.toUpperCase())) {
                        return current;
                    }
                }
            }
            return null;
        }
    }
    
    /**
     * Prints usage to stderr.
     **/
    public static void printUsage()
    {
        System.err.println("Usage:");
        System.err.print("<bitfilename>");
        System.err.print(" ["+COMMAND.CREATE.text+" <size>]");
        System.err.print(" ["+COMMAND.READ.text+" [[-]<filename>]");
        System.err.print(" ["+COMMAND.WRITE.text+" [[-]<filename>]");
        System.err.print(" ["+COMMAND.NONCE.text+" <size>]");
        System.err.println();
        System.err.println(); 
        System.err.println(""+COMMAND.CREATE.text+" <size>");
        System.err.println("  creates a new randomized bitfile of size <size>.");
        System.err.println("  "+Arrays.asList(SI.values()).stream().map(e->""+e.name()+":"+e.getFactor()).collect(Collectors.joining(" "))+" can be used as multipliers");
        System.err.println(""+COMMAND.READ.text+" [-]<targetfilename>");
        System.err.println("  reads a file from passcode <filename> to file of same name or to stdout if given flag - before the filename");
        System.err.println(""+COMMAND.WRITE.text+" [-]<filename>");
        System.err.println("  writes a file to passcode <filename> from file of same name or from stdin if given flag - before the filename");
        System.err.println(""+COMMAND.NONCE.text+" <size>");
        System.err.println("  changes current minimum nonce size and nonce size guess to <size> bytes");
        System.err.println();
    }

    /**
     * Main method for command line interface.
     *
     * @param cliarg command line arguments
     **/
    public static void main(String[] cliarg)
    {
        boolean success = false;
        try {
            ArrayList<String> args = new ArrayList<String>(Arrays.asList(cliarg));
            if(args.size()>0) {
                CommandLineInterface state = openOrCreateBitfile(args);
                while(args.size()>0) {
                    state.consumeAndProcessNextCommand(args);
                }
                success = true;
            }
        }
        catch(IOException ioe) {
            System.err.println("An IOException occurred:");
            ioe.printStackTrace();
        }
        catch(IllegalArgumentException iae) {
            System.err.println("An IllegalArgumentException occurred:");
            iae.printStackTrace();
        }
        if(!success) {
            printUsage();
        }
    }
    
    /**
     * internal functions
     **/
    
    private RandomAccessBitFile bitfile;
    private int nonceSize = 0; // default nonce size is 0 with normal random
    private CommandLineInterface(File bitfile)
    {
        if(null == bitfile) {
            throw new NullPointerException("bitfile is null.");
        }
        if(!bitfile.exists()) {
            throw new IllegalArgumentException("bitfile "+bitfile+" does not exist.");
        }
        this.bitfile = new RandomAccessBitFile(bitfile);
    }
    /*
    private CommandLineInterface(File bitfile, long size)
    {
        RandomAccessBitFile.createNewBitFile(bitfile, size, new SecureRandom());
        this(bitfile);
    }
    */
    private void pipeInputToOutput(InputStream in, OutputStream out)
        throws IOException
    {
        byte[] buf = new byte[BUFSIZE];
        int result = in.read(buf);
        while(-1 != result) {
            out.write(buf, 0, result);
            result = in.read(buf);
        }
        Arrays.fill(buf, (byte)0);
    }
    private void readToOutputStream(char[] name, OutputStream output)
        throws IOException
    {
        try(InputStream input = new FileFinder(bitfile).find(name, nonceSize)) {
            pipeInputToOutput(input, output);
        }
    }
    private void writeFromInputStream(char[] name, InputStream input)
        throws IOException
    {
        try(OutputStream output = StegoOutputStream.open(bitfile, name, nonceSize)) {
            pipeInputToOutput(input, output);
        }
    }
    private static File fileExists(String name)
        throws IOException
    {
        File result = new File(name);
        if(!result.exists()) {
            return null;
        }
        return result;
    }
    /**
     * Checks if command line arguments are either:
     * <bitfilename>
     * or
     * <bitfilename> -c <bitfilesize>
     *
     * @param args command line arguments as list. Correct arguments are consumed from the start of the list.
     * @return CommandLineInterface with opened RandomAccessBitFile
     *
     * @throws IllegalArgumentException if command line arguments were not of either accepted form.
     **/
    private static CommandLineInterface openOrCreateBitfile(List<String> args)
        throws IOException
    {
        String bitfilename = args.remove(0); // filename must be first
        File bitfile = new File(bitfilename);
        if(args.size()>1) {
            if(args.get(0).equals(COMMAND.CREATE.text)) {
                args.remove(0); // COMMAND.CREATE
                String sizeStr = args.remove(0); // size
                try {
                    long size = parseSize(sizeStr); // size
                    if(bitfile.exists()) {
                        throw new IllegalArgumentException("Bitfile "+bitfilename+" already exists.");
                    }
                    RandomAccessBitFile.createNewBitFile(bitfile, size);
                    return new CommandLineInterface(bitfile);
                }
                catch(NumberFormatException nfe) {
                    throw new IllegalArgumentException("Unparseable bitfile size: "+sizeStr, nfe);
                }
            }
        }
        return new CommandLineInterface(bitfile);
    }

    private static long parseSize(String text)
        throws NumberFormatException
    {
        if(null == text) {
            throw new NullPointerException("parseSize text is null.");
        }
        if(text.length()<1) {
            throw new NumberFormatException("parseSize text is empty.");
        }
        SI factor = SI.parse(text.substring(text.length()-1));
        long multiplier = 1l;
        if(null != factor) {
            text = text.substring(0,text.length()-1);
            multiplier = factor.getFactor();
        }
        return multiplier * Long.valueOf(text);
    }
    private void processRead(List<String> args)
        throws IOException
    {
        if(args.size()<1) {
            throw new IllegalArgumentException("Invalid arguments: "+toString(args));
        }
        String targetname = args.remove(0);
        OutputStream out;
        if(targetname.startsWith(PIPENAME)) {
            out = System.out;
            targetname = targetname.substring(PIPENAME.length());
        } else {
            File outFile = new File(targetname);
            if(outFile.exists()) {
                throw new IllegalArgumentException("Outputfile "+outFile+" already exists.");
            } else {
                out = new FileOutputStream(outFile);
            }
        }
        readToOutputStream(targetname.toCharArray(), out);
        return;
    }
    private void processWrite(List<String> args)
        throws IOException
    {
        if(args.size()<1) {
            throw new IllegalArgumentException("Invalid arguments: "+toString(args));
        }
        String sourcename = args.remove(0);
        InputStream in;
        if(sourcename.startsWith(PIPENAME)) {
            in = System.in;
            sourcename = sourcename.substring(PIPENAME.length());
        } else {
            File inFile = new File(sourcename);
            if(!inFile.exists()) {
                throw new IllegalArgumentException("Inputfile "+inFile+" does not exist.");
            } else {
                in = new FileInputStream(inFile);
            }
        }
        writeFromInputStream(sourcename.toCharArray(), in);
        return;
    }
    private void processNonce(List<String> args)
        throws IOException
    {
        if(args.size()<1) {
            throw new IllegalArgumentException("Invalid arguments: "+toString(args));
        }
        String nonceStr = args.remove(0);
        try {
            nonceSize = Integer.valueOf(nonceStr);
        }
        catch(NumberFormatException nfe) {
            throw new IllegalArgumentException("Unparseable nonce size: "+nonceStr, nfe);
        }
    }
    private String toString(List<String> args)
    {
        return args.stream().collect(Collectors.joining(" "));
    }
    private void consumeAndProcessNextCommand(List<String> args)
        throws IOException
    {
        String comstr = "";
        if(args.size()>=2) {
            comstr = args.remove(0);
            COMMAND command = COMMAND.parse(comstr);
            switch(command) {
            case READ: {
                processRead(args);
                return;
            }
            case WRITE: {
                processWrite(args);
                return;
            }
            case NONCE: {
                processNonce(args);
                return;
            }
            default: {// error, so let fall through to exception}
            }
            }
            throw new IllegalArgumentException("Invalid arguments: "+comstr+" "+toString(args));
        }
    }
}
