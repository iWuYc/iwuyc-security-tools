package com.iwuyc.tools.security.digest;

import java.util.Base64;

public class Base64Utils {

    public static String encoding(byte[] bytes) {
        final byte[] base64Bytes = Base64.getMimeEncoder().encode(bytes);
        return new String(base64Bytes);
    }

    public static byte[] decoding(String base64Str) {
        return Base64.getMimeDecoder().decode(base64Str.getBytes());
    }
}
