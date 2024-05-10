package io.jenkins.plugins.eddsa_api;

import hudson.init.InitMilestone;
import hudson.init.Initializer;
import jenkins.security.FIPS140;

/**
 * Prevent the plugin from being used in FIPS mode (it's not compliant in anyway shape or form!)
 */
public class FIPSComplianceCheck {

    @Initializer(fatal = true, before = InitMilestone.PLUGINS_STARTED)
    public static final void preventUsageInFipsMode() throws IllegalStateException {
        if (FIPS140.useCompliantAlgorithms()) {
            throw new IllegalStateException(
                    "The eddsa-api plugin is not FIPS compliant and can not be used in a Jenkins configured to run in FIPS-140 mode");
        }
    }
}
