/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 *
 */
package net.i2p.crypto.eddsa;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import org.junit.jupiter.api.Test;

/**
 * @author str4d
 *
 */
class EdDSASecurityProviderTest {

    @Test
    void canGetInstancesWhenProviderIsPresent() throws Exception {
        Security.addProvider(new EdDSASecurityProvider());

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EdDSA", "EdDSA");
        KeyFactory keyFac = KeyFactory.getInstance("EdDSA", "EdDSA");
        Signature sgr = Signature.getInstance("NONEwithEdDSA", "EdDSA");

        Security.removeProvider("EdDSA");
    }

    @Test
    void cannotGetInstancesWhenProviderIsNotPresent() {
        assertThrows(NoSuchProviderException.class, () -> {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EdDSA", "EdDSA");
        });
    }
}
