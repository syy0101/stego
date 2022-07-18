package stego.ecc;

public class CodingException
    extends Exception
{
    public CodingException()
    {
        super();
    }
    public CodingException(Throwable t)
    {
        super(t);
    }
    public CodingException(String explanation)
    {
        super(explanation);
    }
    public CodingException(String explanation, Throwable t)
    {
        super(explanation, t);
    }
}
