package com.h3xstream.maven.victims;


import com.h3xstream.maven.VersionUtil;
import org.apache.maven.artifact.manager.WagonConfigurationException;
import org.apache.maven.artifact.manager.WagonManager;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.wagon.ConnectionException;
import org.apache.maven.wagon.ResourceDoesNotExistException;
import org.apache.maven.wagon.TransferFailedException;
import org.apache.maven.wagon.UnsupportedProtocolException;
import org.apache.maven.wagon.Wagon;
import org.apache.maven.wagon.authentication.AuthenticationException;
import org.apache.maven.wagon.authorization.AuthorizationException;
import org.apache.maven.wagon.repository.Repository;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class VictimsDbLoader {

    private static final String URL_REPO = "https://github.com/victims/victims-cve-db/";
    private static final String URL_ARCHIVE_FILE = "archive/master.zip";
    private static final String URL_COMMITS_FILE = "commits.atom";

    private Log log; //= new SystemStreamLog()
    private WagonManager wagonManager;

    private Map<String,List<CveVulnerability>> cves;

    /**
     * Matching file like : victims-cve-db-master/database/java/2014/7839.yaml
     */
    private static final Pattern YAML_JAVA_FILE = Pattern.compile("database/java/[\\d]+/[\\d]+.yaml");

    public VictimsDbLoader(Log log,WagonManager wagonManager) {
        this.log = log;
        this.wagonManager = wagonManager;
    }

    public Map<String,List<CveVulnerability>> getRepository() {
        return cves;
    }

    public void loadRepository() {
        this.cves = new HashMap<String,List<CveVulnerability>>();

        String homeDir = System.getProperty("user.home");
        File cacheDir = new File(homeDir, ".victims");
        File archiveDest = new File(cacheDir, "master.zip");
        File commitsDest = new File(cacheDir, "commits.atom");

        try {
            //Create cache directory if nonexistent
            if(!cacheDir.exists()) {
                log.info("Creating victim cache directory "+cacheDir.getCanonicalPath());
                cacheDir.mkdir();
            }

            if(!archiveDest.exists() || !commitsDest.exists()) {
                //Download and write the archive
                Repository rep = new Repository(URL_REPO,URL_REPO);
                Wagon w = wagonManager.getWagon(rep);

                w.connect(rep,wagonManager.getProxy(rep.getProtocol()));
                if(!commitsDest.exists()) {
                    log.info("Downloading the victims atom feed");
                    w.get(URL_COMMITS_FILE, commitsDest);
                }
                if(!archiveDest.exists()) {
                    log.info("Downloading the latest repository");
                    w.get(URL_ARCHIVE_FILE, archiveDest);
                }
            }

            //Extracting the yaml file

            ZipInputStream stream = new ZipInputStream(new FileInputStream(archiveDest));

            for(ZipEntry entry ; (entry = stream.getNextEntry()) !=null; ) {
                if(YAML_JAVA_FILE.matcher(entry.getName()).find()) {
                    //log.info(""+entry.getName());

                    List<String> artifactIds = new ArrayList<String>();
                    CveVulnerability newCve = parseCveYamlFile(stream,artifactIds);

                    for(String artifactId : artifactIds) {
                        //Get the list of CVE for the artifact or create an empty list..
                        List<CveVulnerability> vulns = cves.get(artifactId);
                        if(vulns == null) {
                            vulns = new ArrayList<CveVulnerability>();
                            cves.put(artifactId,vulns);
                        }

                        vulns.add(newCve);
                    }
                }
            }


        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (UnsupportedProtocolException e) {
            throw new RuntimeException(e);
        } catch (WagonConfigurationException e) {
            throw new RuntimeException(e);
        } catch (ConnectionException e) {
            e.printStackTrace();
        } catch (AuthorizationException e) {
            throw new RuntimeException(e);
        } catch (AuthenticationException e) {
            throw new RuntimeException(e);
        } catch (TransferFailedException e) {
            throw new RuntimeException(e);
        } catch (ResourceDoesNotExistException e) {
            throw new RuntimeException(e);
        }
    }

    private CveVulnerability parseCveYamlFile(InputStream in,List<String> outArtifact) {
        Yaml yaml = new Yaml();
        Map<String,Object> obj = (Map<String, Object>) yaml.load(in);

        String cveId = (String) obj.get("cve");
        String title = (String) obj.get("title");
        String description = (String) obj.get("description");
        String cvssScore = obj.get("cvss_v2") != null ? String.valueOf((Double) obj.get("cvss_v2")) : null;
        List<String> references = (List<String>) obj.get("references");

        List<AffectedVersion> parsedVersions = new ArrayList<AffectedVersion>(5);
        List<Map<String,Object>> affectedVersions = (List<Map<String, Object>>) obj.get("affected");
        for(Map<String,Object> version : affectedVersions) {
            String fullArtifactId = version.get("groupId") + ":" + version.get("artifactId");
            List<String> versionsVulnerable = (List<String>) version.get("version");
            parsedVersions.add(new AffectedVersion(fullArtifactId,versionsVulnerable));
            outArtifact.add(fullArtifactId);
        }

        CveVulnerability cve = new CveVulnerability(cveId,title,description,cvssScore,references,parsedVersions);

        return cve;
    }

    public List<CveVulnerability> search(String groupId, String artifactId, String version) {
        List<CveVulnerability> results = new ArrayList<CveVulnerability>();

        String fullArtifactId = groupId+":"+artifactId;
        List<CveVulnerability> vulnerabilities = cves.get(fullArtifactId);

        if(vulnerabilities != null) {
            for(CveVulnerability vuln : vulnerabilities) {

                if(VersionUtil.isAffected(fullArtifactId, version, vuln)) {
                    results.add(vuln);
                }
            }
        }


        return results;
    }
}
