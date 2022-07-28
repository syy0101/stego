package stego.io;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author syy 2022-06-25
 *
 * Lock map class for locking selected resources. Used for locking the bytes of files.
 **/


public class LockMap<T>
    implements AutoCloseable
{
    /**
     * Lock object to use in try-with-resources.
     **/
    public class Lock
	implements AutoCloseable
    {
	private final T target;
	private final Thread me;
	private Lock(T target)
	{
	    this.target = target;
	    this.me = Thread.currentThread();
	}
	public void close()
	    throws RuntimeException
	{
	    if(closingAll) return;
	    if(!lockMap.remove(target, me)) {
		throw new IllegalStateException("lock mismatch with "+target);
	    }
	}
    }
    private Map<T, Thread> lockMap = Collections.synchronizedMap(new HashMap<T, Thread>());
    private boolean closingAll = false;

    /**
     * Locks target T until close() of returned Lock is called. Intended to be used in try-with-resources.
     *
     * @param target the target resource to be locked. T.equals MUST be implemented properly.
     * @returns Lock for target to be held until end of operation OR null if close() has been called before end of locking.
     * @throws IllegalStateException if one tries to lock the same target multiple times from the same thread, as no nested locking is implemented.
     **/
    public Lock lock(T target)
    {
	if(null == target) return null;
	
	final Thread me = Thread.currentThread();

	if(closingAll) return null;

	for(; (null != lockMap.putIfAbsent(target,me)) && !closingAll; Thread.yield()) {
	    if(me.equals(lockMap.get(target))) {
		throw new IllegalStateException("tried to lock multiple times "+target);
	    }
	}

	if(closingAll) return null;

	return new Lock(target);
    }

    /**
     * Signals that no new locks should be allowed to be opened and further closings of currently open locks can be ignored.
     **/
    public void close()
    {
	closingAll = true;
	final int waitMillis = 10;
	for(int waitTrials = 300; !lockMap.isEmpty(); waitTrials--) {
	    try {
		Thread.sleep(waitMillis);
	    }
	    catch (InterruptedException ie) {
	    }
	}
    }

    /**
     * Testing methods
     **/

    /**
     * @returns contents of the lockMap for debugging while testing.
     **/
    private synchronized String contentString()
    {
	synchronized(lockMap) {
	    return
		lockMap.entrySet().stream()
		.map(es -> "["+es.getKey()+";"+es.getValue()+"]")
		.collect(Collectors.joining(";","[","]"));
	}
    }

    /**
     * Test methods.
     **/

    /**
     * Tests if the same thread can lock two different things. Tests that the basic functionality works at all.
     *
     * @returns true if test succeeded, false if it failed.
     **/
    private static boolean testNestedDifferent()
    {
	try(LockMap<Long> A = new LockMap<Long>()) {
	    System.out.println("contents: "+A.contentString());
	    try(LockMap.Lock l1 = A.lock(Long.valueOf(1l))) {
		System.out.println("contents: "+A.contentString());
		try(LockMap.Lock l2 = A.lock(Long.valueOf(2l))) {
		    System.out.println("contents: "+A.contentString());
		}
		System.out.println("contents: "+A.contentString());
	    }
	    System.out.println("contents: "+A.contentString());
	    return true;
	}
    }

    /**
     * Tests if nested locking attempt to same target raises Exception as it should.
     *
     * @returns true if test succeeded and there was an Exception, false otherwise.
     **/
    private static boolean testNestedSame()
    {
	try(LockMap<Long> A = new LockMap<Long>()) {
	    try {
		try(LockMap.Lock l1 = A.lock(Long.valueOf(1l))) {
		    System.out.println("contents: "+A.contentString());
		    try(LockMap.Lock l2 = A.lock(Long.valueOf(1l))) {
			System.out.println("contents: "+A.contentString());
		    }
		    System.out.println("unexpected state, did not throw Exception when multilocking");
		    System.out.println("contents: "+A.contentString());
		}
		System.out.println("contents: "+A.contentString());
	    }
	    catch(IllegalStateException ie) {
		System.out.println("Worked as intended, an Exception when multilocking same resource.");
		return true;
	    }
	    return false;
	}
    }

    /**
     * Tests íf new locks are not granted after closing the LockMap.
     *
     * @returns true if test succeeded and null was returned instead of new Lock after close() call.
     **/
    private static boolean testClosing()
    {
	try(LockMap<Long> A = new LockMap<Long>()) {
	    boolean result = false;
	    A.close();
	    try(LockMap.Lock handle = A.lock(Long.valueOf(3l))) {
		if(null == handle) {
		    System.out.println("Working as intended, null lock after closing.");
		    result = true;
		} else {
		    System.out.println("unexpected state, did not return null after closing but instead "+handle);
		}	    
	    }
	    System.out.println("contents: "+A.contentString());
	    return result;
	}
    }

    /**
     * Tests if different Threads can actually try to lock different and same targets.
     *
     * @returns true if no Exceptions were raised during the test.
     **/
    private static boolean testParallel()
    {
	try {
	    try(LockMap<Long> B = new LockMap<Long>()) {
		System.out.println("B start");
		Set<Runnable> runs = Collections.synchronizedSet(new HashSet<Runnable>());
		for(int i =0; i< 8; i++) {
		    final int myI = i;
		    runs.add(new Runnable() {
			    public void run() {
				try {
				    Thread.sleep(200);
				    System.out.println(B.contentString());
				}
				catch (InterruptedException ie) {
				}
				try(LockMap.Lock Bl0 = B.lock(Long.valueOf(myI))) {
				    try(LockMap.Lock Bl1 = B.lock(Long.valueOf(-1l))) {
					System.out.println(B.contentString());
					System.out.println(myI);
				    }
				}
			    }
			});
		}
		runs.parallelStream().forEach(r -> new Thread(r).start());
		for(int j=0;j<3;j++) {
		    System.out.println(".");
		    try {
			Thread.sleep(1000);
		    }
		    catch(InterruptedException ie) {
		    }
		}
		System.out.println("B end");
	    }
	}
	catch(Exception e) {
	    return false;
	}
	return true;
    }
    /**
     * main method for testing.
     *
     * runs tests and reports their success rate.
     **/
    public static void main(String[] args)
    {
	int successes = 0;
	int trials = 0;

	trials++;
	if(testNestedDifferent()) successes++;

	trials++;
	if(testNestedSame()) successes++;

	trials++;
	if(testClosing()) successes++;

	trials++;
	if(testParallel()) successes++;

	System.out.println("tested "+trials+" trials, "+successes+"/"+trials+" succeeded.");
    }
}
