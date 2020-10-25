package com.iwuyc.tools.security.rsa;

import com.google.common.base.Strings;
import lombok.Data;

/**
 * RSA 密钥对的信息
 *
 * @author Neil
 */
@Data
public class RsaPairPemInfo {
    private String publicKey;
    private String privateKey;

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (hasPublic()) {
            sb.append(publicKey);
        }
        if (hasPrivate()) {
            sb.append(System.lineSeparator());
            sb.append(privateKey);
        }
        return sb.toString();
    }

    /**
     * 是否包含公钥
     * @return 存在公钥，则返回true，否则返回false
     */
    public boolean hasPublic() {
        return !Strings.isNullOrEmpty(publicKey);
    }

    public boolean hasPrivate() {
        return !Strings.isNullOrEmpty(privateKey);
    }
}
