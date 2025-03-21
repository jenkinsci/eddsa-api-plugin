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
package net.i2p.crypto.eddsa.math;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import java.math.BigInteger;
import org.hamcrest.core.*;
import org.junit.jupiter.api.Test;

/**
 * Tests rely on the BigInteger class.
 */
public abstract class AbstractFieldElementTest {

    protected abstract FieldElement getRandomFieldElement();

    protected abstract BigInteger toBigInteger(FieldElement f);

    protected abstract BigInteger getQ();

    protected abstract Field getField();

    // region isNonZero

    protected abstract FieldElement getZeroFieldElement();

    protected abstract FieldElement getNonZeroFieldElement();

    @Test
    void isNonZeroReturnsFalseIfFieldElementIsZero() {
        // Act:
        final FieldElement f = getZeroFieldElement();

        // Assert:
        assertThat(f.isNonZero(), equalTo(false));
    }

    @Test
    void isNonZeroReturnsTrueIfFieldElementIsNonZero() {
        // Act:
        final FieldElement f = getNonZeroFieldElement();

        // Assert:
        assertThat(f.isNonZero(), equalTo(true));
    }

    // endregion

    // region mod q arithmetic

    @Test
    void addReturnsCorrectResult() {
        for (int i = 0; i < 1000; i++) {
            // Arrange:
            final FieldElement f1 = getRandomFieldElement();
            final FieldElement f2 = getRandomFieldElement();
            final BigInteger b1 = toBigInteger(f1);
            final BigInteger b2 = toBigInteger(f2);

            // Act:
            final FieldElement f3 = f1.add(f2);
            final BigInteger b3 = toBigInteger(f3).mod(getQ());

            // Assert:
            assertThat(b3, equalTo(b1.add(b2).mod(getQ())));
        }
    }

    @Test
    void subtractReturnsCorrectResult() {
        for (int i = 0; i < 1000; i++) {
            // Arrange:
            final FieldElement f1 = getRandomFieldElement();
            final FieldElement f2 = getRandomFieldElement();
            final BigInteger b1 = toBigInteger(f1);
            final BigInteger b2 = toBigInteger(f2);

            // Act:
            final FieldElement f3 = f1.subtract(f2);
            final BigInteger b3 = toBigInteger(f3).mod(getQ());

            // Assert:
            assertThat(b3, equalTo(b1.subtract(b2).mod(getQ())));
        }
    }

    @Test
    void negateReturnsCorrectResult() {
        for (int i = 0; i < 1000; i++) {
            // Arrange:
            final FieldElement f1 = getRandomFieldElement();
            final BigInteger b1 = toBigInteger(f1);

            // Act:
            final FieldElement f2 = f1.negate();
            final BigInteger b2 = toBigInteger(f2).mod(getQ());

            // Assert:
            assertThat(b2, equalTo(b1.negate().mod(getQ())));
        }
    }

    @Test
    void multiplyReturnsCorrectResult() {
        for (int i = 0; i < 1000; i++) {
            // Arrange:
            final FieldElement f1 = getRandomFieldElement();
            final FieldElement f2 = getRandomFieldElement();
            final BigInteger b1 = toBigInteger(f1);
            final BigInteger b2 = toBigInteger(f2);

            // Act:
            final FieldElement f3 = f1.multiply(f2);
            final BigInteger b3 = toBigInteger(f3).mod(getQ());

            // Assert:
            assertThat(b3, equalTo(b1.multiply(b2).mod(getQ())));
        }
    }

    @Test
    void squareReturnsCorrectResult() {
        for (int i = 0; i < 1000; i++) {
            // Arrange:
            final FieldElement f1 = getRandomFieldElement();
            final BigInteger b1 = toBigInteger(f1);

            // Act:
            final FieldElement f2 = f1.square();
            final BigInteger b2 = toBigInteger(f2).mod(getQ());

            // Assert:
            assertThat(b2, equalTo(b1.multiply(b1).mod(getQ())));
        }
    }

    @Test
    void squareAndDoubleReturnsCorrectResult() {
        for (int i = 0; i < 1000; i++) {
            // Arrange:
            final FieldElement f1 = getRandomFieldElement();
            final BigInteger b1 = toBigInteger(f1);

            // Act:
            final FieldElement f2 = f1.squareAndDouble();
            final BigInteger b2 = toBigInteger(f2).mod(getQ());

            // Assert:
            assertThat(b2, equalTo(b1.multiply(b1).multiply(new BigInteger("2")).mod(getQ())));
        }
    }

    @Test
    void invertReturnsCorrectResult() {
        for (int i = 0; i < 1000; i++) {
            // Arrange:
            final FieldElement f1 = getRandomFieldElement();
            final BigInteger b1 = toBigInteger(f1);

            // Act:
            final FieldElement f2 = f1.invert();
            final BigInteger b2 = toBigInteger(f2).mod(getQ());

            // Assert:
            assertThat(b2, equalTo(b1.modInverse(getQ())));
        }
    }

    @Test
    void pow22523ReturnsCorrectResult() {
        for (int i = 0; i < 1000; i++) {
            // Arrange:
            final FieldElement f1 = getRandomFieldElement();
            final BigInteger b1 = toBigInteger(f1);

            // Act:
            final FieldElement f2 = f1.pow22523();
            final BigInteger b2 = toBigInteger(f2).mod(getQ());

            // Assert:
            assertThat(b2, equalTo(b1.modPow(BigInteger.ONE.shiftLeft(252).subtract(new BigInteger("3")), getQ())));
        }
    }

    // endregion

    // region cmov

    @Test
    void cmovReturnsCorrectResult() {
        final FieldElement zero = getZeroFieldElement();
        final FieldElement nz = getNonZeroFieldElement();
        final FieldElement f = getRandomFieldElement();

        assertThat(zero.cmov(nz, 0), equalTo(zero));
        assertThat(zero.cmov(nz, 1), equalTo(nz));

        assertThat(f.cmov(nz, 0), equalTo(f));
        assertThat(f.cmov(nz, 1), equalTo(nz));
    }

    // endregion

    // region hashCode / equals

    @Test
    void equalsOnlyReturnsTrueForEquivalentObjects() {
        // Arrange:
        final FieldElement f1 = getRandomFieldElement();
        final FieldElement f2 = getField().getEncoding().decode(f1.toByteArray());
        final FieldElement f3 = getRandomFieldElement();
        final FieldElement f4 = getRandomFieldElement();

        // Assert:
        assertThat(f1, equalTo(f2));
        assertThat(f1, IsNot.not(equalTo(f3)));
        assertThat(f1, IsNot.not(equalTo(f4)));
        assertThat(f3, IsNot.not(equalTo(f4)));
    }

    @Test
    void hashCodesAreEqualForEquivalentObjects() {
        // Arrange:
        final FieldElement f1 = getRandomFieldElement();
        final FieldElement f2 = getField().getEncoding().decode(f1.toByteArray());
        final FieldElement f3 = getRandomFieldElement();
        final FieldElement f4 = getRandomFieldElement();

        // Assert:
        assertThat(f1.hashCode(), equalTo(f2.hashCode()));
        assertThat(f1.hashCode(), IsNot.not(equalTo(f3.hashCode())));
        assertThat(f1.hashCode(), IsNot.not(equalTo(f4.hashCode())));
        assertThat(f3.hashCode(), IsNot.not(equalTo(f4.hashCode())));
    }

    // endregion
}
