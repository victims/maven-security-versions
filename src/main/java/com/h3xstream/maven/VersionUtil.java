package com.h3xstream.maven;

import com.h3xstream.maven.victims.AffectedVersion;
import com.h3xstream.maven.victims.CveVulnerability;
import org.apache.maven.artifact.versioning.ArtifactVersion;
import org.apache.maven.artifact.versioning.DefaultArtifactVersion;
import org.codehaus.mojo.versions.ordering.MavenVersionComparator;

import java.util.Arrays;
import java.util.List;

public class VersionUtil {

    //private static MavenVersionComparator versionComparator = new MavenVersionComparator();

    public static boolean isAffected(String fullArtifactId, String version, CveVulnerability cve) {
        //ArtifactVersion analysedVersion = new DefaultArtifactVersion(version);

        for(AffectedVersion affectedVersion : cve.getAffectedVersions()) {
            if(fullArtifactId.equals(affectedVersion.getFullArtifactId())) {

                versionExpressions : for(String versionExpr : affectedVersion.getLowerThan()) {
                    String[] versionParts = versionExpr.split(",");
                    if(versionParts.length > 1 && !version.startsWith(versionParts[1])) {
                        continue versionExpressions;
                    }

                    if(versionParts[0].startsWith("<=")) {
                        String lastVulnerableVersion = versionParts[0].substring(2);
                        //ArtifactVersion weakVersion = new DefaultArtifactVersion(lastVulnerableVersion);
                        int result = compare(version,lastVulnerableVersion);
                        if(result <= 0) {
                            return true;
                        }
                    }
                }
            }

        }
        return false;
    }

    /**
     * MavenVersionComparator cannot be used efficiently because allot of artifact have invalid version format (ie : 1.3.3.7).
     * The fallback mode when a invalid version is detected doesn't allow a proper comparison to be done.
     *
     * Taken from <a href="http://stackoverflow.com/a/2031954/89769">Cenk Alti Stackoverflow post</a>.
     * @author Cenk Alti
     * @param v1
     * @param v2
     * @return
     */
    private static int compare(String v1, String v2) {
        v1 = v1.replaceAll("\\s", "");
        v2 = v2.replaceAll("\\s", "");
        String[] a1 = v1.split("\\.");
        String[] a2 = v2.split("\\.");
        List<String> l1 = Arrays.asList(a1);
        List<String> l2 = Arrays.asList(a2);


        int i=0;
        while(true){
            Double d1 = null;
            Double d2 = null;

            try{
                d1 = Double.parseDouble(l1.get(i));
            }catch(IndexOutOfBoundsException e){
            }catch(NumberFormatException e){
            }

            try{
                d2 = Double.parseDouble(l2.get(i));
            }catch(IndexOutOfBoundsException e){
            }catch(NumberFormatException e){
            }

            if (d1 != null && d2 != null) {
                if (d1.doubleValue() > d2.doubleValue()) {
                    return 1;
                } else if (d1.doubleValue() < d2.doubleValue()) {
                    return -1;
                }
            } else if (d2 == null && d1 != null) {
                if (d1.doubleValue() > 0) {
                    return 1;
                }
            } else if (d1 == null && d2 != null) {
                if (d2.doubleValue() > 0) {
                    return -1;
                }
            } else {
                break;
            }
            i++;
        }
        return 0;
    }
}
