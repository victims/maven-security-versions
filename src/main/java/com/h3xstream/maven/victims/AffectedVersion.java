package com.h3xstream.maven.victims;


import java.util.List;

public class AffectedVersion {

    private String fullArtifactId;

    private List<String> lowerThan;

    public AffectedVersion(String fullArtifactId, List<String> lowerThan) {
        this.fullArtifactId = fullArtifactId;
        this.lowerThan = lowerThan;
    }

    public String getFullArtifactId() {
        return fullArtifactId;
    }

    public void setFullArtifactId(String fullArtifactId) {
        this.fullArtifactId = fullArtifactId;
    }

    public List<String> getLowerThan() {
        return lowerThan;
    }

    public void setLowerThan(List<String> lowerThan) {
        this.lowerThan = lowerThan;
    }
}
