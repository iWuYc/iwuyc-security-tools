package com.iwuyc.tools.security.rsa.parsers;

import com.google.common.collect.Sets;
import com.iwuyc.tools.security.rsa.RsaPairKey;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;

import java.security.KeyFactory;
import java.util.Optional;
import java.util.Set;

public class Pkcs8EncryptPrivateKeyParser extends Pkcs8PrivateKeyParser {
    @Override
    public Optional<RsaPairKey> parser(PemObjectInfo source) {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");

            PemObject encryptPemObject = source.getPemObject();
            byte[] content = encryptPemObject.getContent();
            JceOpenSSLPKCS8DecryptorProviderBuilder providerBuilder = new JceOpenSSLPKCS8DecryptorProviderBuilder();
            providerBuilder.setProvider(new BouncyCastleProvider());

            PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo = new PKCS8EncryptedPrivateKeyInfo(content);
            char[] password = source.getPassword();
            PrivateKeyInfo privateKeyInfo =
                    pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(providerBuilder.build(password));

            byte[] encoded = privateKeyInfo.getEncoded();

            PemObject pemObject = new PemObject("PRIVATE KEY", encoded);
            PemObjectInfo pemObjectInfo = PemObjectInfo.builder().pemObject(pemObject).build();
            return super.parser(pemObjectInfo);
        } catch (Exception e) {
            e.printStackTrace();
            return Optional.empty();
        }
    }

    @Override
    public boolean isEncrypt(PemObject pemObject) {
        return true;
    }

    @Override
    public Set<String> types() {
        return Sets.newHashSet("ENCRYPTED PRIVATE KEY");
    }
}
