package stego;

public interface DestroyableCloseable
    extends AutoCloseable
{
    public void destroy();
    public boolean isDestroyed();
    public default void close()
    {
        this.destroy();
    }
}
