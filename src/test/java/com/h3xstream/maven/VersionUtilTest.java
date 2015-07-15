package com.h3xstream.maven;

import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class VersionUtilTest {
    @Test
    public void testVulnerableVersion() {
        assertTrue(VersionUtil.isAffected("org.apache.struts:struts2-core", "2.1.6", VulnerabilityFixtures.vulnerabilityStruts1));
        assertTrue(VersionUtil.isAffected("org.apache.struts:struts2-core", "2.3.16.1", VulnerabilityFixtures.vulnerabilityStruts1));
    }

    @Test
    public void testSafeVersion() {
        assertFalse(VersionUtil.isAffected("org.apache.struts:struts2-core", "2.3.16.2", VulnerabilityFixtures.vulnerabilityStruts1));
        //2.4.0 doesn't exist yet .. just to test the version parsing.
        assertFalse(VersionUtil.isAffected("org.apache.struts:struts2-core", "2.4.0", VulnerabilityFixtures.vulnerabilityStruts1));
    }
}
