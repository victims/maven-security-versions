package com.h3xstream.maven.tpl;

import org.apache.maven.project.MavenProject;

import java.util.List;

public class ProjectSummary {

    private final MavenProject project;
    private final List<VulnerableLibrary> libraries;

    public ProjectSummary(MavenProject project, List<VulnerableLibrary> libraries) {
        this.project = project;
        this.libraries = libraries;
    }

    public List<VulnerableLibrary> getLibraries() {
        return libraries;
    }

    public MavenProject getProject() {
        return project;
    }
}
