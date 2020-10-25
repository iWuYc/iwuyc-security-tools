package com.iwuyc.tools.security.rsa.parsers;

import lombok.Builder;
import lombok.Data;
import org.bouncycastle.util.io.pem.PemObject;

@Data
@Builder
public class PemObjectInfo {
    private PemObject pemObject;
    private char[] password;
}
