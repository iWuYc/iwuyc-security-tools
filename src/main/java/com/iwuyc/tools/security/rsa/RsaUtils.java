package com.iwuyc.tools.security.rsa;

import com.iwuyc.tools.digest.Base64Utils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.*;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;

import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.*;

/**
 * @author Neil
 */
public class RsaUtils {
    static {
        Security.addProvider(new BouncyCastleProvider());
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

    public static Optional<RsaPairPemInfo> toPem(RsaPairKey rsaPairKey) {
        return toPem(rsaPairKey, null);
    }

    public static Optional<RsaPairPemInfo> toPem(RsaPairKey rsaPairKey, char[] password) {
        try {

            // Public Key
            PemObjectGenerator publicPemObjGen = new JcaMiscPEMGenerator(rsaPairKey.getPublicKey(), null);
            String pubPemStr = toPemStr(publicPemObjGen);

            // Private Key
            final JceOpenSSLPKCS8EncryptorBuilder jceOpenSslPkcs8EncryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_aes256_CBC.getId()));
            OutputEncryptor encryptor;
            if (null != password && password.length > 0) {
                encryptor = jceOpenSslPkcs8EncryptorBuilder.setPasssword(password).build();
            } else {
                encryptor = null;
            }
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
            return publicWrite.toString();
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * 从pem文件中加载私钥
     *
     * @param pemFile   pem文件
     * @param passwords pem文件中，加密密钥对应的密码列表
     * @return pem文件中密钥对的列表
     */
    public static List<RsaPairKey> loadPriKeyFromPem(File pemFile, char[]... passwords) {
        try (final FileInputStream fis = new FileInputStream(pemFile)) {
            return loadPriKeyFromPem(fis, passwords);
        } catch (IOException e) {
            return Collections.emptyList();
        }
    }

    /**
     * 从pem格式的字符串中加载私钥
     *
     * @param pemContent pem文件
     * @param passwords  pem文件中，加密密钥对应的密码列表
     * @return pem文件中密钥对的列表
     */
    public static List<RsaPairKey> loadPriKeyFromPem(String pemContent, char[]... passwords) {
        try (final ByteArrayInputStream bais = new ByteArrayInputStream(pemContent.getBytes())) {
            return loadPriKeyFromPem(bais, passwords);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Collections.emptyList();
    }

    /**
     * 从pem格式的流数据中加载私钥
     *
     * @param is        数据输入流
     * @param passwords pem文件中，加密密钥对应的密码列表
     * @return pem文件中密钥对的列表
     */
    public static List<RsaPairKey> loadPriKeyFromPem(InputStream is, char[]... passwords) {
        try (InputStreamReader isr = new InputStreamReader(is);
             final PEMParser pemParser = new PEMParser(isr)) {
            Object pemInfo;
            List<RsaPairKey> rsaPairKeys = new ArrayList<>();
            int passwordIndex = 0;
            while (null != (pemInfo = pemParser.readObject())) {
                JceOpenSSLPKCS8DecryptorProviderBuilder providerBuilder = new JceOpenSSLPKCS8DecryptorProviderBuilder();
                providerBuilder.setProvider(new BouncyCastleProvider());

                PrivateKeyInfo privateKeyInfo;
                if (pemInfo instanceof PKCS8EncryptedPrivateKeyInfo) {
                    PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) pemInfo;
                    if (passwordIndex >= passwords.length) {
                        throw new IllegalArgumentException("index:[" + passwordIndex + "]未找到相应的密码。");
                    }
                    final char[] password = passwords[passwordIndex];
                    privateKeyInfo = pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(providerBuilder.build(password));
                    passwordIndex++;
                } else if (pemInfo instanceof PrivateKeyInfo) {
                    privateKeyInfo = (PrivateKeyInfo) pemInfo;
                } else if (pemInfo instanceof PEMKeyPair) {
                    final PEMKeyPair pemKeyPair = (PEMKeyPair) pemInfo;
                    privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
                } else {
                    continue;
                }
                final AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory.createKey(privateKeyInfo);
                if (!(asymmetricKeyParameter instanceof RSAPrivateCrtKeyParameters)) {
                    continue;
                }

                final RSAPrivateCrtKeyParameters key = (RSAPrivateCrtKeyParameters) asymmetricKeyParameter;
                final KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                KeySpec pubKeySpec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
                final RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);

                KeySpec priKeySpec = new RSAPrivateKeySpec(key.getModulus(), key.getP());
                final RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(priKeySpec);

                rsaPairKeys.add(new RsaPairKey(publicKey, privateKey));
            }
            return Collections.unmodifiableList(rsaPairKeys);
        } catch (Exception e) {
            e.printStackTrace();
            return Collections.emptyList();
        }
    }


    /**
     * 从pem格式的字符串中读取公钥
     *
     * @param pemContent pem格式的字符串，非文件的路径
     * @return 公钥列表
     */
    public static List<RSAPublicKey> loadPubKeyFromPem(String pemContent) {
        try (final ByteArrayInputStream bais = new ByteArrayInputStream(pemContent.getBytes())) {
            return loadPubKeyFromPem(bais);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Collections.emptyList();
    }

    public static List<RSAPublicKey> loadPubKeyFromPem(File pemFile) {
        try (final FileInputStream fis = new FileInputStream(pemFile)) {
            return loadPubKeyFromPem(fis);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Collections.emptyList();
    }

    public static List<RSAPublicKey> loadPubKeyFromPem(InputStream is) {
        try (final InputStreamReader reader = new InputStreamReader(is);
             final PEMParser pemParser = new PEMParser(reader)) {
            Object pemObj;
            List<RSAPublicKey> rsaPublicKeys = new ArrayList<>();
            while (null != (pemObj = pemParser.readObject())) {
                if (!(pemObj instanceof SubjectPublicKeyInfo)) {
                    continue;
                }
                final SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) pemObj;

                final byte[] modulus = subjectPublicKeyInfo.getEncoded();
                final KeySpec pubKeySpec = new X509EncodedKeySpec(modulus);
                final KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                final RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
                rsaPublicKeys.add(publicKey);
            }

            return Collections.unmodifiableList(rsaPublicKeys);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return Collections.emptyList();
    }
}
