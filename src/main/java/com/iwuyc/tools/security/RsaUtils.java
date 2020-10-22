package com.iwuyc.tools.security;

import com.iwuyc.tools.digest.Base64Utils;
import lombok.Data;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.*;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;

import javax.swing.text.html.Option;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Collection;
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
        private RSAPublicKey publicKey;
        private RSAPrivateKey privateKey;

        public RsaPairKey(KeyPair keyPair) {
            this((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());
        }

        public RsaPairKey(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public boolean hasPrivate() {
            return null != privateKey;
        }
    }

    @Data
    public static class RsaPairPemInfo {
        private String publicKey;
        private String privateKey;
    }

    /**
     * 生成公钥和私钥
     *
     * @return 将生成的密钥对返回给调用方
     */
    public static Optional<RsaPairKey> generator() {
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

    public static Optional<RsaPairPemInfo> toPem(RsaPairKey rsaPairKey) {
        return toPem(rsaPairKey, null);
    }

    public static Optional<RsaPairPemInfo> toPem(RsaPairKey rsaPairKey, char[] password) {
        try {

            // Public Key
            PemObjectGenerator publicPemObjGen = new JcaMiscPEMGenerator(rsaPairKey.getPublicKey(), null);
            String pubPemStr = toPemStr(publicPemObjGen);

            // Private Key
            OutputEncryptor encryptor =
                    new JceOpenSSLPKCS8EncryptorBuilder(new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_aes256_CBC.getId())).setPasssword(password).build();
            PemObjectGenerator privatePemObjGen = new JcaPKCS8Generator(rsaPairKey.getPrivateKey(), encryptor);
            String privatePemStr = toPemStr(privatePemObjGen);

            RsaPairPemInfo result = new RsaPairPemInfo();
            result.setPublicKey(pubPemStr);
            result.setPrivateKey(privatePemStr);

            return Optional.of(result);

        } catch (OperatorCreationException | IOException e) {
            throw new IllegalArgumentException("转换格式的时候出现异常。msg:" + e.getMessage(), e);
        }
    }

    private static String toPemStr(PemObjectGenerator pemObjectGenerator) {
        try (final StringWriter publicWrite = new StringWriter();
             final JcaPEMWriter publicJcaPemWriter = new JcaPEMWriter(publicWrite)) {


            final PemObject publicPemObj = pemObjectGenerator.generate();
            publicJcaPemWriter.writeObject(publicPemObj);
            publicJcaPemWriter.flush();
            final String pubPemStr = publicWrite.toString();
            System.out.println(pubPemStr);
            return pubPemStr;
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static Optional<Collection<RsaPairKey>> fromPemStr(String pemStr, char[] password) {
        try (StringReader reader = new StringReader(pemStr);
             final PEMParser pemParser = new PEMParser(reader);) {
            Object pemInfo;
            Collection<RsaPairKey> rsaPairKeys = new ArrayList<>();
            while (null != (pemInfo = pemParser.readObject())) {
                JceOpenSSLPKCS8DecryptorProviderBuilder providerBuilder = new JceOpenSSLPKCS8DecryptorProviderBuilder();
                providerBuilder.setProvider(new BouncyCastleProvider());


                PrivateKeyInfo privateKeyInfo;
                if (pemInfo instanceof PKCS8EncryptedPrivateKeyInfo) {
                    PKCS8EncryptedPrivateKeyInfo o = (PKCS8EncryptedPrivateKeyInfo) pemInfo;
                    privateKeyInfo = o.decryptPrivateKeyInfo(providerBuilder.build(password));
                } else if (pemInfo instanceof PrivateKey) {
                    privateKeyInfo = (PrivateKeyInfo) pemInfo;
                } else {
                    continue;
                }

                PKCS8EncryptedPrivateKeyInfo o = (PKCS8EncryptedPrivateKeyInfo) pemInfo;
//            PrivateKeyInfo privateKeyInfo = o.decryptPrivateKeyInfo(providerBuilder.build("ssss".toCharArray()));
                final RSAPrivateCrtKeyParameters key = (RSAPrivateCrtKeyParameters) PrivateKeyFactory.createKey(privateKeyInfo);

                final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                KeySpec pubKeySpec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
                final RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
                KeySpec priKeySpec = new RSAPrivateKeySpec(key.getModulus(), key.getP());
                final RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(priKeySpec);
                rsaPairKeys.add(new RsaPairKey(publicKey, privateKey));
            }
            return Optional.of(rsaPairKeys);
        } catch (Exception e) {
            e.printStackTrace();
            return Optional.empty();
        }

    }
}
