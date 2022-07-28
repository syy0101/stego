package stego.io;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.util.function.Supplier;

public class FileUtil
{
    public static Supplier<InputStream> createInputStreamSupplier(File source)
    {
	return new Supplier<InputStream>() {
	    public InputStream get() {
		try {
		    return new FileInputStream(source);
		}
		catch(IOException ioe) {
		    throw new UncheckedIOException(ioe);
		}
	    }
	};
    }
    public static Supplier<OutputStream> createOutputStreamSupplier(File source)
    {
	return new Supplier<OutputStream>() {
	    public OutputStream get() {
		try {
		    return new FileOutputStream(source);
		}
		catch(IOException ioe) {
		    throw new UncheckedIOException(ioe);
		}
	    }
	};
    }
}
