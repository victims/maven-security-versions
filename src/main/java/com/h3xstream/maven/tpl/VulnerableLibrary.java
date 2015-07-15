package com.h3xstream.maven.tpl;

import com.h3xstream.maven.victims.CveVulnerability;
import org.apache.maven.artifact.Artifact;

import java.util.List;

public class VulnerableLibrary {

    private final Artifact artifact;
    private final List<Artifact> hierarchyChain;
    private final List<CveVulnerability> vulnerabilities;

    public VulnerableLibrary(Artifact artifact, List<CveVulnerability> vulnerabilities,List<Artifact> hierarchyChain) {
        this.artifact = artifact;
        this.vulnerabilities = vulnerabilities;
        this.hierarchyChain = hierarchyChain;
    }

    public Artifact getArtifact() {
        return artifact;
    }

    public List<CveVulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public List<Artifact> getHierarchyChain() {
        return hierarchyChain;
    }
}
