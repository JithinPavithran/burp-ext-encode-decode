package encode;

public class None implements Encoder{
    @Override
    public String getName() {
        return "None (Do nothing)";
    }

    @Override
    public byte[] encode(byte[] input) {
        return input;
    }

    @Override
    public byte[] decode(byte[] input) {
        return input;
    }
}
