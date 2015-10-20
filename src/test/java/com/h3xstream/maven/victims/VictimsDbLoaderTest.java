package com.h3xstream.maven.victims;

import org.testng.annotations.Test;

import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertTrue;

public class VictimsDbLoaderTest {

    @Test
    public void testDataLoaded() {
        VictimsDbLoader loader = MockVictimsDbLoader.createMock();
        loader.loadRepository();

        Map<String,List<CveVulnerability>> cves = loader.getRepository();

        assertTrue(cves.size()>0, "Unable to load any CVE");
    }
}
