package com.h3xstream.maven.victims;

import org.testng.annotations.Test;

import java.util.List;

import static org.testng.Assert.assertTrue;

public class VictimsDbLoaderSearchTest {


    @Test
    public void testSearch() {
        VictimsDbLoader loader = MockVictimsDbLoader.createMock();
        loader.loadRepository();

        List<CveVulnerability> vulnerabilities = loader.search("org.apache.struts", "struts2-core", "2.1.6");
        assertTrue(vulnerabilities.size() > 0, "Old Struts dependencies not found.");

    }
}
