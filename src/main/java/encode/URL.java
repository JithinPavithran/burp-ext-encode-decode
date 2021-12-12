package encode;


import org.apache.commons.text.StringEscapeUtils;

import java.nio.charset.StandardCharsets;

public class URL implements Encoder {

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
        String str = new String(input, StandardCharsets.UTF_8);
        str = StringEscapeUtils.unescapeJava(str);
        return str.getBytes(StandardCharsets.UTF_8);
    }
}
