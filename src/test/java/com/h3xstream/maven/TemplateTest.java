package com.h3xstream.maven;

import com.h3xstream.maven.tpl.VulnerableLibrary;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class TemplateTest {
    @Test
    public void makeSureTemplateStillCompile() throws Exception {

        SecurityVersionsCheck mojo = new SecurityVersionsCheck();

        mojo.exportToHtml(VulnerabilityFixtures.projects,System.out);

        //TODO Some assertion on the result
    }
}
