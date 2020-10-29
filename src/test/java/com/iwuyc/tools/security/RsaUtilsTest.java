package com.iwuyc.tools.security;

import com.iwuyc.tools.digest.Base64Utils;
import com.iwuyc.tools.security.rsa.RsaPairKey;
import com.iwuyc.tools.security.rsa.RsaPairPemInfo;
import com.iwuyc.tools.security.rsa.RsaUtils;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.RSAUtil;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class RsaUtilsTest {
    private static final String CLASSPATH_ROOT = RsaUtils.class.getResource("/").getPath().substring(1);
    final char[] password = "ssss".toCharArray();

    @Test
    public void generator() {
        final Optional<RsaPairKey> keysOpt = RsaUtils.generator();
        Assert.assertTrue(keysOpt.isPresent());
        Optional<RsaPairPemInfo> rsaPairPemInfoOpt = RsaUtils.toPem(keysOpt.get(), password);
        Assert.assertTrue(rsaPairPemInfoOpt.isPresent());
        RsaPairPemInfo rsaPairPemInfo = rsaPairPemInfoOpt.get();
        System.out.println(rsaPairPemInfo);

    }

    @Test
    public void loadFromPem() {
        List<RsaPairKey> rsaPairKeys = RsaUtils.loadPriKeyFromPem(new File(CLASSPATH_ROOT + File.separatorChar + "privateKey" +
                ".pem"));
        RsaPairKey rsaPairKey = rsaPairKeys.get(0);
        Optional<RsaPairPemInfo> rsaPairPemInfoOpt = RsaUtils.toPem(rsaPairKey);
        Assert.assertTrue(rsaPairPemInfoOpt.isPresent());
        System.out.println(rsaPairPemInfoOpt.get());

        String content = "hello world.";
        Optional<String> encryptOpt = RsaUtils.encrypt(content, rsaPairKey.getPublicKey());
        Assert.assertTrue(encryptOpt.isPresent());
        String encryptContent = encryptOpt.get();

        Optional<String> decryptOpt = RsaUtils.decrypt(encryptContent, rsaPairKey.getPrivateKey());
        Assert.assertTrue(decryptOpt.isPresent());
        Assert.assertEquals(content, decryptOpt.get());

    }

    @Test
    public void loadFromPemEncrypt() {
        List<RsaPairKey> rsaPairKeys = RsaUtils.loadPriKeyFromPem(new File(CLASSPATH_ROOT + File.separatorChar + "privateKeyEncrypt.pem")
                , password);
        RsaPairKey rsaPairKey = rsaPairKeys.get(0);
        Optional<RsaPairPemInfo> rsaPairPemInfoOpt = RsaUtils.toPem(rsaPairKey);
        Assert.assertTrue(rsaPairPemInfoOpt.isPresent());
        System.out.println(rsaPairPemInfoOpt.get());

        String content = "hello world.";
        Optional<String> encryptOpt = RsaUtils.encrypt(content, rsaPairKey.getPublicKey());
        Assert.assertTrue(encryptOpt.isPresent());
        String encryptContent = encryptOpt.get();

        Optional<String> decryptOpt = RsaUtils.decrypt(encryptContent, rsaPairKey.getPrivateKey());
        Assert.assertTrue(decryptOpt.isPresent());
        Assert.assertEquals(content, decryptOpt.get());
        System.out.println("Test Case Success!");

    }

    @Test
    public void loadFromOpensslPemEncrypt() {
        List<RsaPairKey> rsaPairKeys = RsaUtils.loadPriKeyFromPem(new File(CLASSPATH_ROOT + File.separatorChar + "privateKeyOpenSsl.pem"), "123456".toCharArray());
        Assert.assertTrue(rsaPairKeys.size() > 0);
        RsaPairKey rsaPairKey = rsaPairKeys.get(0);
        Optional<RsaPairPemInfo> rsaPairPemInfoOpt = RsaUtils.toPem(rsaPairKey);
        Assert.assertTrue(rsaPairPemInfoOpt.isPresent());
        System.out.println(rsaPairPemInfoOpt.get());

        String content = "hello world.";
        Optional<String> encryptOpt = RsaUtils.encrypt(content, rsaPairKey.getPublicKey());
        Assert.assertTrue(encryptOpt.isPresent());
        String encryptContent = encryptOpt.get();

        Optional<String> decryptOpt = RsaUtils.decrypt(encryptContent, rsaPairKey.getPrivateKey());
        Assert.assertTrue(decryptOpt.isPresent());
        Assert.assertEquals(content, decryptOpt.get());
        System.out.println("Test Case Success!");

    }

    @Test
    public void decryptByOpenssl() {

        List<RsaPairKey> rsaPairKeys = RsaUtils.loadPriKeyFromPem(new File(CLASSPATH_ROOT + File.separatorChar + "privateKeyOpenSsl.pem"), "123456".toCharArray());
        final RsaPairKey rsaPairKey = rsaPairKeys.get(0);
        System.out.println(rsaPairKey);
        System.out.println(RsaUtils.toPem(rsaPairKey));

        // encrypt by public key,and using private key decrypt it.
        String pubEncryptContent = readFile(Paths.get(CLASSPATH_ROOT, "encrypt", "test_encrypt_by_pub.bin").toFile());
        System.out.println(pubEncryptContent);
        final Optional<String> decryptPubContent = RsaUtils.decrypt(pubEncryptContent, rsaPairKey.getPrivateKey());
        System.out.println(decryptPubContent);

        // encrypt by private key,and using public key decrypt it.
        String priEncryptContent = readFile(Paths.get(CLASSPATH_ROOT, "encrypt", "test_encrypt_by_pri.bin").toFile());
        System.out.println(priEncryptContent);
        final Optional<String> decryptPriContent = RsaUtils.decrypt(priEncryptContent, rsaPairKey.getPublicKey());
        System.out.println(decryptPriContent);


        final String srcData = "hello world!";
        final Optional<String> encrypt = RsaUtils.encrypt(srcData, rsaPairKey.getPublicKey());
        final Optional<String> decrypt = RsaUtils.decrypt(encrypt.orElse(null), rsaPairKey.getPrivateKey());
        System.out.println(srcData.equals(decrypt.orElse(null)));
    }

    private String readFile(File file) {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] bytes = new byte[1024];
            int len = 0;
            StringBuilder sb = new StringBuilder();
            while ((len = fis.read(bytes)) > 0) {
                sb.append(Base64Utils.encoding(Arrays.copyOf(bytes, len)));
            }
            return sb.toString();
        } catch (Exception e) {

        }
        return null;
    }
}
