package com.iwuyc.tools.security;

import com.iwuyc.tools.security.digest.Base64Utils;
import lombok.Data;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;

import java.io.StringReader;
import java.io.StringWriter;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Optional;

/**
 * @author Neil
 */
public class RsaUtils {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     *
     */
    @Data
    public static class RsaPairKey {
        public RsaPairKey(KeyPair keyPair) {
            this((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());
        }

        public RsaPairKey(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        private RSAPublicKey publicKey;
        private RSAPrivateKey privateKey;

    }

    /**
     * 生成公钥和私钥
     */
    public static Optional<RsaPairKey> crtGenerator() {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();
            return Optional.of(new RsaPairKey(keyPair));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("生成RSA公私钥的时候产生了异常：" + e.getMessage(), e);
        }
    }

    public static Optional<RsaPairKey> readCrt(String publicKeyStr, String privateKeyStr) {
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            final PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64Utils.decoding(privateKeyStr));
            final RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8EncodedKeySpec);

            final X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64Utils.decoding(publicKeyStr));
            final RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);
            return Optional.of(new RsaPairKey(publicKey, privateKey));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("读取RSA公私钥的时候产生了异常：" + e.getMessage(), e);
        }
    }

    public static Optional<String> toPemStr(RsaPairKey rsaPairKey) {
        try (StringWriter write = new StringWriter(); final JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(write);) {
            OutputEncryptor encryptor =
                    new JceOpenSSLPKCS8EncryptorBuilder(new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_aes256_CBC.getId())).setPasssword("ssss".toCharArray()).build();
            PemObjectGenerator pemObjGen = new JcaPKCS8Generator(rsaPairKey.getPrivateKey(), encryptor);
            final PemObject generate = pemObjGen.generate();
            jcaPEMWriter.writeObject(generate);
            jcaPEMWriter.flush();
            final String pemStr = write.toString();
            System.out.println(pemStr);
            return Optional.of(pemStr);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return Optional.empty();
    }

    public static Optional<RsaPairKey> fromPemStr(String pemStr) {
        try (StringReader reader = new StringReader(pemStr);
             final PEMParser pemParser = new PEMParser(reader);) {
            PemObject pemObject = pemParser.readPemObject();

            PKCS8EncryptedPrivateKeyInfo o = (PKCS8EncryptedPrivateKeyInfo) pemParser.readObject();
            JceOpenSSLPKCS8DecryptorProviderBuilder providerBuilder = new JceOpenSSLPKCS8DecryptorProviderBuilder();
            providerBuilder.setProvider(new BouncyCastleProvider());

            PrivateKeyInfo privateKeyInfo = o.decryptPrivateKeyInfo(providerBuilder.build("ssss".toCharArray()));
            System.out.println(o);
            return Optional.empty();
        } catch (Exception e) {
            e.printStackTrace();
            return Optional.empty();
        }

    }
}
