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
package net.i2p.crypto.eddsa.math.ed25519;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import net.i2p.crypto.eddsa.math.*;
import org.junit.jupiter.api.Test;

/**
 * Tests rely on the BigInteger class.
 */
class Ed25519FieldElementTest extends AbstractFieldElementTest {

    protected FieldElement getRandomFieldElement() {
        return MathUtils.getRandomFieldElement();
    }

    protected BigInteger toBigInteger(FieldElement f) {
        return MathUtils.toBigInteger(f);
    }

    protected BigInteger getQ() {
        return MathUtils.getQ();
    }

    protected Field getField() {
        return MathUtils.getField();
    }

    // region constructor

    @Test
    void canConstructFieldElementFromArrayWithCorrectLength() {
        // Assert:
        new Ed25519FieldElement(MathUtils.getField(), new int[10]);
    }

    @Test
    void cannotConstructFieldElementFromArrayWithIncorrectLength() {
        assertThrows(IllegalArgumentException.class, () -> {
            // Assert:
            new Ed25519FieldElement(MathUtils.getField(), new int[9]);
        });
    }

    @Test
    void cannotConstructFieldElementWithoutField() {
        assertThrows(IllegalArgumentException.class, () -> {
            // Assert:
            new Ed25519FieldElement(null, new int[9]);
        });
    }

    // endregion

    // region isNonZero

    protected FieldElement getZeroFieldElement() {
        return new Ed25519FieldElement(MathUtils.getField(), new int[10]);
    }

    protected FieldElement getNonZeroFieldElement() {
        final int[] t = new int[10];
        t[0] = 5;
        return new Ed25519FieldElement(MathUtils.getField(), t);
    }

    // endregion

    // region toString

    @Test
    void toStringReturnsCorrectRepresentation() {
        // Arrange:
        final byte[] bytes = new byte[32];
        for (int i = 0; i < 32; i++) {
            bytes[i] = (byte) (i + 1);
        }
        final FieldElement f = MathUtils.getField().getEncoding().decode(bytes);

        // Act:
        final String fAsString = f.toString();
        final StringBuilder builder = new StringBuilder();
        builder.append("[Ed25519FieldElement val=");
        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }
        builder.append("]");

        // Assert:
        assertThat(fAsString, equalTo(builder.toString()));
    }

    // endregion
}
