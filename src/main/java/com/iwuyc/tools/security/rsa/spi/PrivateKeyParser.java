package com.iwuyc.tools.security.rsa.spi;

import com.iwuyc.tools.security.rsa.RsaPairKey;
import com.iwuyc.tools.security.rsa.parsers.PemObjectInfo;
import org.bouncycastle.util.io.pem.PemObject;

import java.util.Optional;
import java.util.Set;

public interface PrivateKeyParser {

    Optional<RsaPairKey> parser(PemObjectInfo source);

     Set<String> types();

    boolean isEncrypt(PemObject pemObject);
}
