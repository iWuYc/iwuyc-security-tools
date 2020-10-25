package com.iwuyc.tools.security.rsa.parsers;

import com.google.common.collect.Sets;
import com.iwuyc.tools.security.rsa.RsaPairKey;
import com.iwuyc.tools.security.rsa.spi.PrivateKeyParser;
import org.bouncycastle.util.io.pem.PemObject;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Optional;
import java.util.Set;

public class Pkcs8PrivateKeyParser implements PrivateKeyParser {
    @Override
    public Optional<RsaPairKey> parser(PemObjectInfo source) {
        try {

            PemObject pemObject = source.getPemObject();
            final byte[] content = pemObject.getContent();
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(content);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(keySpec);

            RSAPrivateCrtKey privk = (RSAPrivateCrtKey) privateKey;

            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privk.getModulus(), privk.getPublicExponent());

            PublicKey publicKey = kf.generatePublic(publicKeySpec);

            return Optional.of(new RsaPairKey((RSAPublicKey) publicKey, (RSAPrivateKey) privateKey));
        } catch (Exception e) {
            e.printStackTrace();
            return Optional.empty();
        }
    }

    @Override
    public boolean isEncrypt(PemObject pemObject) {
        return false;
    }

    @Override
    public Set<String> types() {
        return Sets.newHashSet("PRIVATE KEY");
    }
}
