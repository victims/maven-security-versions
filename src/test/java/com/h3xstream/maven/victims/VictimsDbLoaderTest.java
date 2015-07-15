package com.h3xstream.maven.victims;

import org.apache.maven.artifact.manager.DefaultWagonManager;
import org.apache.maven.plugin.logging.SystemStreamLog;
import org.testng.annotations.Test;

import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertTrue;


public class VictimsDbLoaderTest {

    @Test
    public void testDataLoaded() {
        VictimsDbLoader loader = new VictimsDbLoader(new SystemStreamLog(),new DefaultWagonManager());
        loader.loadRepository();

        Map<String,List<CveVulnerability>> cves = loader.getRepository();

        assertTrue(cves.size()>0,"Unable to load any CVE");
    }
}
