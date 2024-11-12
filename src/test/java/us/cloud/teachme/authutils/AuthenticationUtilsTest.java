package us.cloud.teachme.authutils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuthenticationUtilsTest {

    @ParameterizedTest(name = "Path \"{0}\" with protected paths {1} should return {2}")
    @CsvSource({
            // Single protected path cases
            "/api/test, '/api/test', true",
            "/api/test, '/api/*', true",
            "/api/other, '/api/test', false",
            "/api/test/sub, '/api/test/*', true",
            "/public, '/api/*', false",

            // Exact matches in a list of protected paths
            "/api/admin, '/api/test,/api/admin', true",
            "/api/admin/settings, '/api/admin,/api/admin/*', true",
            "/api/user, '/api/admin,/api/test', false",
            "/api/user/profile, '/api/user,/api/user/profile', true",

            // Wildcard matches in a list of protected paths
            "/api/products/123, '/api/products/*,/api/orders/*', true",
            "/api/orders/456, '/api/products/*,/api/orders/*', true",
            "/api/customers/789, '/api/products/*,/api/orders/*', false",

            // Mixed exact and wildcard patterns
            "/api/admin, '/api/*,/api/user', true",
            "/api/user/profile, '/api/user,/api/user/profile', true",
            "/api/test, '/api/admin,/api/test', true",
            "/api/admin/settings, '/api/admin/settings,/api/*', true",
            "/api/open/resource, '/api/private,/api/secure/*', false",

            // No match with multiple paths
            "/public/resource, '/api/test,/api/user,/api/admin/*', false",
            "/api/other, '/api/admin,/api/user', false"
    })
    @DisplayName("Parameterized test for needsAuthentication with multiple paths")
    void testNeedsAuthentication(String path, String protectedPaths, boolean expected) {
        boolean authNeeded = AuthenticationUtils.needsAuthentication(path, protectedPaths.split(","));
        assertEquals(expected, authNeeded);
    }
}
