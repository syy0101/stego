package stego.util;

import java.io.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import stego.io.*;

/**
 * Command line interface for stegodata.
 *
 * @author syy 2022-07-17
 **/

public class CommandLineInterface
    implements AutoCloseable
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
	NONCE("-n"),
	/**
	 * changes new password for output bitfile
	 **/
	NEWPASSWORD("-p"),
	/**
	 * specifies input bitfile
	 **/
	INPUTFILE("-i");

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
    }
    
    /**
     * Prints usage to stderr.
     **/
    public static void printUsage()
    {
	System.err.println("Usage:");
	System.err.print("<bitfilename>");
	System.err.print(" ["+COMMAND.WRITE.text+" [-]<filename>");
	System.err.print(" ("+COMMAND.CREATE.text+" <size>|"+COMMAND.INPUTFILE.text+" <inputfile>)]");
	System.err.print(" ["+COMMAND.READ.text+" [-]<filename>]");
	System.err.print(" ["+COMMAND.NONCE.text+" <size>]");
	System.err.print(" ["+COMMAND.NEWPASSWORD.text+"]");
	System.err.println();
	System.err.println(); 
	System.err.println(""+COMMAND.CREATE.text+" <size>");
	System.err.println("  creates a new randomized bitfile of size <size>.");
	System.err.println("  "+Arrays.asList(SI.values()).stream().map(e->""+e.name()+":"+e.getFactor()).collect(Collectors.joining(" "))+" can be used as multipliers");
	System.err.println(""+COMMAND.READ.text+" [-]<targetfilename>");
	System.err.println("  reads a file from passcode <filename> to file of same name or to stdout if given flag - before the filename");
	System.err.println(""+COMMAND.WRITE.text+" <filename>");
	System.err.println("  writes a file to passcode <filename> from file of same name or from stdin if given flag - before the filename");
	System.err.println(""+COMMAND.NONCE.text+" <size>");
	System.err.println("  changes current minimum nonce size and nonce size guess to <size> bytes");
	System.err.println(""+COMMAND.NEWPASSWORD.text+"");
	System.err.println("  changes new password for the output bitfile");
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
		CommandLineInterface state = new CommandLineInterface();
		success = state.processCommands(args.remove(0),mapCommands(args));
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
    
    private char[] outPasscode = null;
    private char[] inPasscode = null;
    private int nonceSize = 1; // default nonce size is 1 with normal random
    private long outFilesize = -1l;
    private ReadonlyBitFile inbitfile = null;
    private CommandLineInterface()
    {
    }
    public boolean processCommands(String bitfileName, Map<COMMAND, List<String>> commands)
	throws IOException
    {
	if(commands.containsKey(null)) {
	    throw new IllegalArgumentException("unknown arguments: "+Arrays.deepToString(commands.get(null).toArray()));
	}
	File outFile = null;
	File inFile = null;
	if(commands.containsKey(COMMAND.NONCE)) {
	    List<String> nonceArguments = commands.get(COMMAND.NONCE);
	    if(nonceArguments.size() != 1) {
		throw new IllegalArgumentException("wrong amount of "+COMMAND.NONCE.text+" parameters.");
	    }
	    nonceSize = Integer.valueOf(nonceArguments.remove(0));
	    commands.remove(COMMAND.NONCE);
	}
	if(commands.containsKey(COMMAND.WRITE)) {
	    outFile = new File(bitfileName);
	    if(commands.containsKey(COMMAND.CREATE)) {
		if(commands.containsKey(COMMAND.INPUTFILE)) {
		    throw new IllegalArgumentException("both "+COMMAND.CREATE.text+" and "+COMMAND.INPUTFILE.text+" used.");
		}
		List<String> createArguments = commands.get(COMMAND.CREATE);
		if(createArguments.size() != 1) {
		    throw new IllegalArgumentException("wrong amount of "+COMMAND.CREATE.text+" parameters.");
		}
		outFile = new File(bitfileName);
		outFilesize = SI.parseSize(createArguments.remove(0));
		outPasscode = queryPassword("outfile password:",2);
	    } else {
		if(!commands.containsKey(COMMAND.INPUTFILE)) {
		    throw new IllegalArgumentException("neither "+COMMAND.CREATE.text+" nor "+COMMAND.INPUTFILE.text+" used.");
		}
		List<String> inputfileArguments = commands.get(COMMAND.INPUTFILE);
		if(inputfileArguments.size() != 1) {
		    throw new IllegalArgumentException("wrong amount of "+COMMAND.INPUTFILE.text+" parameters.");
		}
		inFile = new File(inputfileArguments.remove(0));
		inPasscode = queryPassword("infile password:",1);
		if(commands.containsKey(COMMAND.NEWPASSWORD)) {
		    outPasscode = queryPassword("outfile password:",2);
		    commands.remove(COMMAND.NEWPASSWORD);
		} else {
		    outPasscode = inPasscode;
		}
		commands.remove(COMMAND.INPUTFILE);
	    }
	} else {
	    if(commands.containsKey(COMMAND.CREATE)) {
		if(commands.containsKey(COMMAND.INPUTFILE)) {
		    throw new IllegalArgumentException("both "+COMMAND.CREATE.text+" and "+COMMAND.INPUTFILE.text+" used.");
		}
		List<String> createArguments = commands.get(COMMAND.CREATE);
		if(createArguments.size() != 1) {
		    throw new IllegalArgumentException("wrong amount of "+COMMAND.CREATE.text+" parameters.");
		}
		outFile = new File(bitfileName);
		outFilesize = SI.parseSize(createArguments.remove(0));
		outPasscode = queryPassword("outfile password:",2);
	    } else {
		inFile = new File(bitfileName);
		inPasscode = queryPassword("infile password:",1);
	    }
	}
	if(commands.containsKey(COMMAND.READ)) {
	    if(null == inFile) {
		throw new IllegalArgumentException("can't read without existing bitfile.");
	    }
	    try(ReadonlyBitFile openedInBitfile = ReadonlyBitFile.read(inFile, inPasscode, new SecureRandom())) {
		List<String> readFiles = commands.get(COMMAND.READ);
		for(String readName : readFiles) {
		    OutputStream out = null;
		    if(readName.startsWith(PIPENAME)) {
			readName = readName.substring(PIPENAME.length());
			out = System.out;
		    } else {
			File readFile = new File(readName);
			if(readFile.exists()) {
			    throw new IllegalArgumentException(""+readName+" already exists.");
			}
			out = new FileOutputStream(readFile);
		    }
		    InputStream in
			= new FileFinder(openedInBitfile)
			.find(readName.toCharArray(), nonceSize);
		    pipeInputToOutput(in, out);
		}
	    }
	    commands.remove(COMMAND.READ);
	}
	if(commands.containsKey(COMMAND.WRITE)) {
	    List<String> writeNames = commands.get(COMMAND.WRITE);
	    for(String name : writeNames) {
		File f = new File(name);
		if(!f.exists()) {
		    throw new IllegalArgumentException("file "+name+" not found.");
		}
	    }
	    List<FileHider> fileHiders
		= writeNames.stream()
		.map(s -> new FileHider(new File(s), nonceSize, new SecureRandom()))
		.collect(Collectors.toList());
	    if(null != inFile) {
		try(ReadonlyBitFile inBitfile = ReadonlyBitFile.read(inFile, inPasscode, new SecureRandom())) {
		    ProtectedFileSlice
			.write(inBitfile,
			       new FileOutputStream(outFile), outPasscode, nonceSize, new SecureRandom(),
			       fileHiders).close();
		}
	    } else {
		ProtectedFileSlice.createAndWrite(outFilesize, new FileOutputStream(outFile), outPasscode, nonceSize, new SecureRandom(), fileHiders).close();
	    }
	    commands.remove(COMMAND.WRITE);
	    if(commands.containsKey(COMMAND.CREATE)) {
		commands.remove(COMMAND.CREATE);
	    }
	} else {
	    if(commands.containsKey(COMMAND.CREATE)) {
		ProtectedFileSlice.createAndWrite(outFilesize, new FileOutputStream(outFile), outPasscode, nonceSize, new SecureRandom(), Arrays.asList()).close();
	    }
	    commands.remove(COMMAND.CREATE);
	}	
	if(!commands.isEmpty()) {
	    System.err.println("Unprocessed commands left at end of execution: "+Arrays.deepToString(commands.entrySet().toArray()));
	    return false;
	}
	return true;
    }

    public static char[] queryPassword(String message, int inputCounts)
    {
	if(inputCounts<1) {
	    throw new IllegalArgumentException("Trying to query "+inputCounts+" passwords.");
	}
	System.console().writer().println(message);
	char[][] passcode = new char[inputCounts][];
	for(int i=0;i<inputCounts;i++) {
	    if(i>0) {
		System.console().writer().println("again:");
	    }
	    passcode[i] = System.console().readPassword();
	}
	boolean match = true;
	for(int pw = 1; pw<passcode.length; pw++) {
	    if(passcode[0].length != passcode[pw].length) {
		match = false;
	    } else {
		for(int j = 0; j<passcode[0].length; j++) {
		    match = match && (passcode[0][j] == passcode[pw][j]);
		}
	    }
	    Arrays.fill(passcode[pw],' ');
	}
	if(!match) {
	    throw new IllegalArgumentException("password mismatch.");
	}
	return passcode[0];
    }
    public void close()
    {
	try {
	    if(null != outPasscode) {
		Arrays.fill(outPasscode, ' ');
	    }
	}
	finally {
	    if(null != inPasscode) {
		Arrays.fill(inPasscode, ' ');
	    }
	}
    }
    private static Map<COMMAND, List<String>> mapCommands(List<String> args)
    {
	HashMap<COMMAND, List<String>> result = new HashMap<COMMAND, List<String>>(COMMAND.values().length);
	while(args.size()>0) {
	    COMMAND command = COMMAND.parse(args.remove(0));
	    switch(command) {
	    case NEWPASSWORD: {
		result.put(COMMAND.NEWPASSWORD, Arrays.asList("password"));
		break;
	    }
	    default: {
		result
		    .computeIfAbsent(command,
				     k -> new ArrayList<String>()
				     )
		    .add(args.isEmpty()
			 ? ""
			 : args.remove(0)
			 );
	    }
	    }
	}
	
	return result;	
    }
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
    public static void showProgress()
    {
	Console con = System.console();
	if(null != con) {
	    Date now = new Date();
	    final String messageMarks = "-\\|/";
	    System.console().writer().print(""+messageMarks.charAt(Math.floorMod(now.getTime(),messageMarks.length()))+"\b");
	    System.console().writer().flush();
	}
    }
}
