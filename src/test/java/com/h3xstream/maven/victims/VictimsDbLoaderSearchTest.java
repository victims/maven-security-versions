package com.h3xstream.maven.victims;

import org.apache.maven.artifact.manager.DefaultWagonManager;
import org.apache.maven.plugin.logging.SystemStreamLog;
import org.testng.annotations.Test;

import java.util.List;

import static org.testng.Assert.assertTrue;

public class VictimsDbLoaderSearchTest {
    @Test
    public void testSearch() {

        VictimsDbLoader loader = new VictimsDbLoader(new SystemStreamLog(),new DefaultWagonManager());
        loader.loadRepository();

        List<CveVulnerability> vulnerabilities = loader.search("org.apache.struts", "struts2-core", "2.1.6");
        assertTrue(vulnerabilities.size()>0,"Old Struts dependencies not found.");
    }
}
