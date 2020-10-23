package com.iwuyc.tools.security;

import com.iwuyc.tools.digest.Base64Utils;
import com.iwuyc.tools.security.rsa.RsaPairKey;
import com.iwuyc.tools.security.rsa.RsaPairPemInfo;
import com.iwuyc.tools.security.rsa.RsaUtils;
import org.junit.Assert;
import org.junit.Test;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Collection;
import java.util.Optional;

public class RsaUtilsTest {
    final char[] password = "ssss".toCharArray();

    @Test
    public void name() {
        final Optional<RsaPairKey> keys = RsaUtils.generator();
        Assert.assertTrue(keys.isPresent());
        final RsaPairKey rsaPairKey = keys.get();
        final RSAPrivateKey privateKey = rsaPairKey.getPrivateKey();
        String privateKeyStr = Base64Utils.encoding(privateKey.getEncoded());


        final RSAPublicKey publicKey = rsaPairKey.getPublicKey();
        final String publicKeyStr = new String(Base64.getEncoder().encode(publicKey.getEncoded()));
        System.out.println(publicKeyStr);

        RsaUtils.readCrt(publicKeyStr, privateKeyStr);


        Optional<RsaPairPemInfo> pemStrOpt = RsaUtils.toPem(rsaPairKey, password);
        Assert.assertTrue(pemStrOpt.isPresent());
        RsaPairPemInfo pemStr = pemStrOpt.get();
        Optional<Collection<RsaPairKey>> rsaPairKey1;
//        rsaPairKey1 = RsaUtils.fromPemStr(pemStr.getPrivateKey());
//        System.out.println(rsaPairKey1);

        rsaPairKey1 = RsaUtils.fromPemStr(pemStr.getPrivateKey() + pemStr.getPublicKey(), password);
        System.out.println(rsaPairKey1);
    }
}
