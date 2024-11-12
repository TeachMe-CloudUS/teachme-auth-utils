package us.cloud.teachme.authutils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AuthenticationUtils {

    public static boolean needsAuthentication(String currentPath, String[] protectedPaths) {
        for (String path : protectedPaths) {
            if (path.endsWith("/*")) {
                String basePath = path.substring(0, path.length() - 2);
                if (currentPath.startsWith(basePath)) {
                    return true;
                }
            }
            else if (currentPath.equals(path)) {
                return true;
            }
        }
        return false;
    }

    public static PublicKey loadPublicKey(Path path) throws Exception {
        String publicKeyPem = Files.readString(path)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(publicKeyPem);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }
}
