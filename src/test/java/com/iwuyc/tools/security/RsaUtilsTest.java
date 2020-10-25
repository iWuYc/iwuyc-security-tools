package com.iwuyc.tools.security;

import com.iwuyc.tools.security.rsa.RsaPairKey;
import com.iwuyc.tools.security.rsa.RsaPairPemInfo;
import com.iwuyc.tools.security.rsa.RsaUtils;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.util.List;
import java.util.Optional;

public class RsaUtilsTest {
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
        List<RsaPairKey> rsaPairKeys = RsaUtils.loadPriKeyFromPem(new File("F:\\Workspace\\Github\\iwuyc-security-tools\\src\\main\\resources\\privateKey.pem"));
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
        List<RsaPairKey> rsaPairKeys = RsaUtils.loadPriKeyFromPem(new File("F:\\Workspace\\Github\\iwuyc-security" +
                "-tools\\src\\main\\resources\\privateKeyEncrypt.pem"), password);
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
        List<RsaPairKey> rsaPairKeys = RsaUtils.loadPriKeyFromPem(new File("F:\\Workspace\\Github\\iwuyc-security" +
                "-tools\\src\\main\\resources\\privateKeyOpenSsl.pem"), "123456".toCharArray());
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
}
