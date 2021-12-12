package encode;

public interface Encoder {
    public String getName();
    public byte[] encode(byte[] input);
    public byte[] decode(byte[] input);
}
