package com.iwuyc.tools.security.rsa.parsers;

import com.google.common.collect.Sets;
import com.iwuyc.tools.security.rsa.RsaPairKey;
import com.iwuyc.tools.security.rsa.spi.PrivateKeyParser;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;

import java.util.*;

@SuppressWarnings("unchecked")
public class RsaPrivateKeyParser implements PrivateKeyParser {
    @Override
    public Optional<RsaPairKey> parser(PemObjectInfo source) {
        PemObject pemObject = source.getPemObject();
        List<PemHeader> headers = pemObject.getHeaders();
        Map<String, PemHeader> headerNameMap = new HashMap<>(headers.size());
        for (PemHeader header : headers) {
            headerNameMap.put(header.getName(), header);
        }
        boolean encrypt = isEncrypt(pemObject);
        if (encrypt) {
            PemHeader dekInfoHeader = headerNameMap.get("DEK-Info");
            StringTokenizer tknz = new StringTokenizer(dekInfoHeader.getValue(), ",");
            String dekAlgName = tknz.nextToken();
            byte[] iv = Hex.decode(tknz.nextToken());
//            new PEMEncryptedKeyPair(dekAlgName, iv, keyBytes, pemKeyPairParser)
//            return new PEMEncryptedKeyPair(dekAlgName, iv, keyBytes, pemKeyPairParser);
        }

        return Optional.empty();
    }

    @Override
    public Set<String> types() {
        return Sets.newHashSet("RSA PRIVATE KEY");
    }

    @Override
    public boolean isEncrypt(PemObject pemObject) {
        List<PemHeader> headers = pemObject.getHeaders();
        for (PemHeader header : headers) {
            if ("Proc-Type".equals(header.getName())) {
                return "4,ENCRYPTED".equals(header.getValue());
            }
        }
        return false;
    }
}
