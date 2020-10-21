package com.iwuyc.tools.security;

import com.iwuyc.tools.security.digest.Base64Utils;
import org.junit.Assert;
import org.junit.Test;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Optional;

public class RsaUtilsTest {
    @Test
    public void name() {
        final Optional<RsaUtils.RsaPairKey> keys = RsaUtils.crtGenerator();
        Assert.assertTrue(keys.isPresent());
        final RsaUtils.RsaPairKey rsaPairKey = keys.get();
        final RSAPrivateKey privateKey = rsaPairKey.getPrivateKey();
        String privateKeyStr = Base64Utils.encoding(privateKey.getEncoded());


        final RSAPublicKey publicKey = rsaPairKey.getPublicKey();
        final String publicKeyStr = new String(Base64.getEncoder().encode(publicKey.getEncoded()));
        System.out.println(publicKeyStr);

        RsaUtils.readCrt(publicKeyStr, privateKeyStr);


        Optional<String> pemStrOpt = RsaUtils.toPemStr(rsaPairKey);
        Assert.assertTrue(pemStrOpt.isPresent());
        String pemStr = pemStrOpt.get();
        Optional<RsaUtils.RsaPairKey> rsaPairKey1 = RsaUtils.fromPemStr(pemStr);
        System.out.println(rsaPairKey1);
    }
}
