package com.h3xstream.maven.victims;


import com.h3xstream.maven.VersionUtil;
import com.h3xstream.maven.http.HttpRepository;
import com.h3xstream.maven.http.WagonHttpRepository;
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
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import org.yaml.snakeyaml.Yaml;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class VictimsDbLoader {

    private static final String URL_ARCHIVE_FILE = "archive/master.zip";
    private static final String URL_COMMITS_FILE = "commits.atom";

    private Log log; //= new SystemStreamLog()
    private WagonManager wagonManager;

    private Map<String,List<CveVulnerability>> cves;

    protected HttpRepository repo;

    /**
     * Matching file like : victims-cve-db-master/database/java/2014/7839.yaml
     */
    private static final Pattern YAML_JAVA_FILE = Pattern.compile("database/java/[\\d]+/[\\d]+.yaml");

    public VictimsDbLoader(final Log log,final WagonManager wagonManager) throws WagonConfigurationException, UnsupportedProtocolException, ConnectionException, AuthenticationException {
        this.log = log;
        this.wagonManager = wagonManager;
        if(wagonManager != null) {
            this.repo = new WagonHttpRepository(log,wagonManager);
        }
    }

    public Map<String,List<CveVulnerability>> getRepository() {
        return cves;
    }

    public void loadRepository() {
        this.cves = new HashMap<String,List<CveVulnerability>>();

        String homeDir = System.getProperty("user.home");
        File cacheDir = new File(homeDir, ".victims");
        File victimsRepoFile = new File(cacheDir, "master.zip");
        File versionFile = new File(cacheDir, "version.txt");

        try {
            //Create cache directory if nonexistent
            if(!cacheDir.exists()) {
                log.info("Creating victim cache directory "+cacheDir.getCanonicalPath());
                cacheDir.mkdir();
            }

            ////Loading the version (date)
            log.info("Syncing with the victims repository (based on the atom feed)");
            File tempAtomFeed = File.createTempFile("commits-atom", ".xml");
            log.debug("Temp file: " + tempAtomFeed.getCanonicalPath());
            repo.getFile(URL_COMMITS_FILE, tempAtomFeed);

            ////Comparing the version with the local one
            String latestVersion = getLatestVersion(tempAtomFeed);
            String localeVersion = getFileContent(versionFile);

            log.debug(String.format("Latest version %s, Locale version %s",latestVersion,localeVersion));

            if(latestVersion.equals(localeVersion)) {
                log.info("Already to the latest version.");
            }
            else {
                if(victimsRepoFile.exists()) {
                    log.info("Removing existing database.");
                    victimsRepoFile.delete();
                }
                if(versionFile.exists()) {
                    versionFile.delete();
                }

                log.debug("Downloading the latest repository");
                repo.getFile(URL_ARCHIVE_FILE, victimsRepoFile);

                //Keep the version of the downloaded file
                writeVersionFile(versionFile, latestVersion);
            }

            //Extracting the yaml file

            ZipInputStream stream = new ZipInputStream(new FileInputStream(victimsRepoFile));

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



        } catch (Exception e) {
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


    public String getLatestVersion(File atomFile) throws IOException, ParserConfigurationException, SAXException, XPathExpressionException {
        DocumentBuilderFactory objDocumentBuilderFactory = DocumentBuilderFactory.newInstance();
        //objDocumentBuilderFactory.setAttribute(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        objDocumentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);//Just in case..
        DocumentBuilder objDocumentBuilder = objDocumentBuilderFactory.newDocumentBuilder();
        XPath xPath = XPathFactory.newInstance().newXPath();

        Document doc = objDocumentBuilder.parse(new FileInputStream(atomFile));
        String latestVersion = xPath.compile("/feed/updated").evaluate(doc);
        if(latestVersion == null) {
            throw new RuntimeException("Unable to read the latest commits feed.");
        }
        return latestVersion;
    }

    private String getFileContent(File versionFile) throws FileNotFoundException {
        return (!versionFile.exists()) ? null : new Scanner(versionFile).useDelimiter("\\A").next();
    }

    private void writeVersionFile(File versionFile, String version) throws FileNotFoundException, UnsupportedEncodingException {
        PrintWriter writer = new PrintWriter(new FileOutputStream(versionFile, false));
        writer.print(version);
        writer.close();
    }

}
