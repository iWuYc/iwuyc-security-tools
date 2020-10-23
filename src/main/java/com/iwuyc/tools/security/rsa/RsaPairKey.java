package com.iwuyc.tools.security.rsa;

import lombok.Data;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 *
 */
@Data
public class RsaPairKey {
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
