package us.cloud.teachme.authutils;

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
}
