package encode;

import java.io.ByteArrayOutputStream;

public class UnicodeSlashU implements Encoder {

    @Override
    public String getName() {
        return "Decode Unicode (\\u0041 ⮕ A)";
    }

    @Override
    public byte[] encode(byte[] input) {
        return new byte[0];
    }

    @Override
    public byte[] decode(byte[] input) {
        return input;
    }
}
