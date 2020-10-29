package com.iwuyc.tools.security.rsa;

import com.google.common.collect.Sets;
import com.iwuyc.tools.digest.Base64Utils;
import com.iwuyc.tools.security.rsa.parsers.PemObjectInfo;
import com.iwuyc.tools.security.rsa.spi.PrivateKeyParser;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;

import javax.crypto.Cipher;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * @author Neil
 */
@SuppressWarnings("unused")
@Slf4j
public class RsaUtils {
    private static final Map<String, PrivateKeyParser> PEM_PARSER_MAP;

    static {
        Security.addProvider(new BouncyCastleProvider());
        ServiceLoader<PrivateKeyParser> pemParsers = ServiceLoader.load(PrivateKeyParser.class);
        final Map<String, PrivateKeyParser> temp = new HashMap<>();
        for (PrivateKeyParser privateKeyParser : pemParsers) {
            Set<String> types = privateKeyParser.types();
            for (String type : types) {
                temp.put(type, privateKeyParser);
            }
        }
        PEM_PARSER_MAP = Collections.unmodifiableMap(temp);
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
            e.printStackTrace();
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

    private static final Set<String> PRIVAT3E_KEY_TYPE =
            Collections.unmodifiableSet(Sets.newHashSet("ENCRYPTED PRIVATE KEY", "PRIVATE KEY"));

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
            PemObject pemObject;
            List<RsaPairKey> rsaPairKeys = new ArrayList<>();
            int passwordIndex = 0;
            while (null != (pemObject = pemParser.readPemObject())) {
                final PrivateKeyParser privateKeyParser = PEM_PARSER_MAP.get(pemObject.getType());
                if (null == privateKeyParser) {
                    continue;
                }
                PemObjectInfo.PemObjectInfoBuilder pemObjectInfoBuilder = PemObjectInfo.builder();
                pemObjectInfoBuilder.pemObject(pemObject);
                if (privateKeyParser.isEncrypt(pemObject)) {
                    pemObjectInfoBuilder.password(passwords[passwordIndex]);
                }
                Optional<RsaPairKey> rsaPairKeyOpt = privateKeyParser.parser(pemObjectInfoBuilder.build());
                if (!rsaPairKeyOpt.isPresent()) {
                    log.warn("未能解析出私钥信息。pemObject:{}", pemObject);
                    continue;
                }
                rsaPairKeys.add(rsaPairKeyOpt.get());
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

    /**
     * 公钥加密
     *
     * @param data 待加密的数据
     * @param key  公钥
     */
    public static Optional<String> encrypt(String data, Key key) {
        try {
            final BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();

            //RSA加密
            Cipher cipher = Cipher.getInstance("RSA",bouncyCastleProvider);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return Optional.of(Base64Utils.encoding(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8))));
        } catch (Exception e) {
            e.printStackTrace();
            return Optional.empty();
        }
    }

    public static Optional<String> decrypt(String str, Key key) {
        //64位解码加密后的字符串
        byte[] inputByte = Base64Utils.decoding(str);
        //base64编码的私钥
        //RSA解密
        Runtime.getRuntime().addShutdownHook(new Thread(()->{

        }));

        try {
            final BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
            Cipher cipher = Cipher.getInstance("RSA",bouncyCastleProvider);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return Optional.of(new String(cipher.doFinal(inputByte)));
        } catch (Exception e) {
            e.printStackTrace();
            return Optional.empty();
        }
    }
}
