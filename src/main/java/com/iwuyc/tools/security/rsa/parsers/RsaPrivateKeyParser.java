package com.iwuyc.tools.security.rsa.parsers;

import com.google.common.collect.Sets;
import com.iwuyc.tools.security.rsa.RsaPairKey;
import com.iwuyc.tools.security.rsa.spi.PrivateKeyParser;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKeyStructure;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMDecryptor;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

@SuppressWarnings("unchecked")
public class RsaPrivateKeyParser extends Pkcs8PrivateKeyParser {
    ///RSAPrivateKeyStructure asn1PrivKey = new RSAPrivateKeyStructure((ASN1Sequence) ASN1Sequence.fromByteArray(priKeyData));
    //RSAPrivateKeySpec rsaPrivKeySpec = new RSAPrivateKeySpec(asn1PrivKey.getModulus(), asn1PrivKey.getPrivateExponent());
    @Override
    public Optional<RsaPairKey> parser(PemObjectInfo source) {
        try {
            PemObject pemObject = source.getPemObject();
            List<PemHeader> headers = pemObject.getHeaders();
            Map<String, PemHeader> headerNameMap = new HashMap<>(headers.size());
            for (PemHeader header : headers) {
                headerNameMap.put(header.getName(), header);
            }
            boolean encrypt = isEncrypt(pemObject);
            final byte[] privateKeyContent;
            if (encrypt) {
                PemHeader dekInfoHeader = headerNameMap.get("DEK-Info");
                StringTokenizer tknz = new StringTokenizer(dekInfoHeader.getValue(), ",");
                String dekAlgName = tknz.nextToken();
                byte[] iv = Hex.decode(tknz.nextToken());

                char[] password = source.getPassword();
                PEMDecryptorProvider keyDecryptProvider = new JcePEMDecryptorProviderBuilder().build(password);
                final PEMDecryptor pemDecryptor = keyDecryptProvider.get(dekAlgName);
                final byte[] encryptContent = pemObject.getContent();
                privateKeyContent = pemDecryptor.decrypt(encryptContent, iv);
            } else {
                privateKeyContent = pemObject.getContent();
            }

            final PemObject decryptPemObject = new PemObject(super.types().iterator().next(), privateKeyContent);
            final PemObjectInfo pemObjectInfo = PemObjectInfo.builder().pemObject(decryptPemObject).build();
            return super.parser(pemObjectInfo);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return Optional.empty();
    }

    private PEMKeyPair parserToKey(byte[] decryptContent) throws IOException {
        ASN1Sequence seq = ASN1Sequence.getInstance(decryptContent);

        if (seq.size() != 9) {
            throw new PEMException("malformed sequence in RSA private key");
        }

        org.bouncycastle.asn1.pkcs.RSAPrivateKey keyStruct = org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(seq);

        RSAPublicKey pubSpec = new RSAPublicKey(
                keyStruct.getModulus(), keyStruct.getPublicExponent());

        AlgorithmIdentifier algId = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);

        return new PEMKeyPair(new SubjectPublicKeyInfo(algId, pubSpec), new PrivateKeyInfo(algId, keyStruct));

    }

    @Override
    public Set<String> types() {
        return Sets.newHashSet("RSA PRIVATE KEY");
    }

    @Override
    public boolean isEncrypt(PemObject pemObject) {
        List<PemHeader> headers = pemObject.getHeaders();
        for (PemHeader header : headers) {
            if ("Proc-Type".equals(header.getName())) {
                return "4,ENCRYPTED".equals(header.getValue());
            }
        }
        return false;
    }
}
