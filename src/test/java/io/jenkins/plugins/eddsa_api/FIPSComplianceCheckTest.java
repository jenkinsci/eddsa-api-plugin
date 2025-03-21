package io.jenkins.plugins.eddsa_api;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import jenkins.model.Jenkins;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.RealJenkinsRule;
import org.jvnet.hudson.test.RealJenkinsRule.JenkinsStartupException;

public class FIPSComplianceCheckTest {

    @Rule
    public RealJenkinsRule rjr = new RealJenkinsRule();

    @Test
    public void testStartupNonFips() throws Throwable {
        rjr.javaOptions("-Xmx128M");
        rjr.then(r -> {
            Jenkins.get().getPluginManager().uberClassLoader.loadClass("net.i2p.crypto.eddsa.EdDSAEngine");
        });
    }

    @Test
    public void testStartupFips() {
        rjr.javaOptions("-Xmx128M", "-Djenkins.security.FIPS140.COMPLIANCE=true");
        JenkinsStartupException jse = assertThrows(
                JenkinsStartupException.class,
                () -> rjr.then(r -> {
                    Jenkins.get().getPluginManager().uberClassLoader.loadClass("net.i2p.crypto.eddsa.EdDSAEngine");
                    fail("should not get here!");
                }));
        assertThat(
                jse.getMessage(),
                containsString(
                        "The eddsa-api plugin is not FIPS compliant and can not be used in a Jenkins configured to run in FIPS-140 mode"));
    }
}
