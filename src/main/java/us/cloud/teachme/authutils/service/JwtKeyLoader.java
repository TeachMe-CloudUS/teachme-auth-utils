package us.cloud.teachme.authutils.service;

import org.springframework.core.io.Resource;
import org.springframework.util.StreamUtils;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class JwtKeyLoader {

    /**
     * Loads an RSA public key from a PEM formatted resource.
     * Supports both PKCS#8 and X.509 formats.
     *
     * @param resource Spring Resource containing the public key
     * @return the public key
     * @throws Exception if the key cannot be loaded or is invalid
     */
    public static PublicKey loadPublicKey(Resource resource) throws Exception {
        String pemContent = StreamUtils.copyToString(
                resource.getInputStream(),
                StandardCharsets.UTF_8
        );

        String publicKeyPem = pemContent
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        try {
            byte[] decoded = Base64.getDecoder().decode(publicKeyPem);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(new X509EncodedKeySpec(decoded));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid public key format", e);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load public key", e);
        }
    }
}
