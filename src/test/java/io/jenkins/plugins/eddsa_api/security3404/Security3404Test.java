package io.jenkins.plugins.eddsa_api.security3404;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.security.MessageDigest;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.stream.Stream;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class Security3404Test {

    private static final EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);

    static Stream<Arguments> parameters() {
        // See https://eprint.iacr.org/2020/1244.pdf Table 6 c), as well as Section 5.1 for an explanation that these
        // signatures are supposed to fail to ensure SUF-CMA property
        return Stream.of(
                Arguments.arguments(
                        "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
                        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
                        "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514"),
                Arguments.arguments(
                        "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
                        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
                        "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22"));
    }

    @ParameterizedTest
    @MethodSource("parameters")
    void testCases5And6(String messageHex, String publicKeyHex, String signatureHex) {
        assertThat(verify_i2p(messageHex, publicKeyHex, signatureHex), is(false));
    }
    /**
     * Return EdDSAPublicKey object from the hex representation of the compressed Edwards public key point.
     **/
    // Code used under Apache 2.0 license from
    // https://github.com/novifinancial/ed25519-speccheck/blob/main/scripts/ed25519-java/src/main/java/Ed25519TestCase.java
    private EdDSAPublicKey decodePublicKey(String publicKeyHex) throws InvalidKeySpecException {
        byte[] pk = Utils.hexToBytes(publicKeyHex);
        byte[] x509pk = EncodingUtils.compressedEd25519PublicKeyToX509(pk);
        X509EncodedKeySpec encoded = new X509EncodedKeySpec(x509pk);
        return new EdDSAPublicKey(encoded);
    }

    /**
     * Pure Ed25519 signature verification using the i2p lib, it returns false if it fails or if an exception occurs).
     **/
    // Code used under Apache 2.0 license from
    // https://github.com/novifinancial/ed25519-speccheck/blob/main/scripts/ed25519-java/src/main/java/Ed25519TestCase.java
    public boolean verify_i2p(String messageHex, String publicKeyHex, String signatureHex) {
        try {
            EdDSAPublicKey publicKey = decodePublicKey(publicKeyHex);
            byte[] messageBytes = Utils.hexToBytes(messageHex);
            byte[] signatureBytes = Utils.hexToBytes(signatureHex);
            EdDSAEngine sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
            sgr.initVerify(publicKey);
            return sgr.verifyOneShot(messageBytes, signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }
}
