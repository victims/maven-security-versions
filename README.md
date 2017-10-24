# Maven Security Versions [![Build Status](https://secure.travis-ci.org/GoSecure/maven-security-versions.png?branch=master)](http://travis-ci.org/GoSecure/maven-security-versions) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.h3xstream.maven/security-versions/badge.svg)](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.h3xstream.maven%22%20a%3A%22security-versions%22)

Identify vulnerable libraries in Maven dependencies.

The plugin is based on **[versions-maven-plugin](http://www.mojohaus.org/versions-maven-plugin/)**. It use the victims database has source for CVEs and Maven artifact mapping.


## Screenshot

![Animate screenshot](https://raw.githubusercontent.com/GoSecure/maven-security-versions/master/demos/screenshots/screen1.gif)

## Usage

    > mvn com.h3xstream.maven:security-versions:check
    [INFO] Scanning for projects...
    [INFO]
    [INFO] ------------------------------------------------------------------------
    [INFO] Building Demo Insecure Project 1.0.0-SNAPSHOT
    [INFO] ------------------------------------------------------------------------
    [INFO]
    [INFO] --- security-versions:1.0.2:check (default-cli) @ demo-insecure-project ---
    [INFO] Analyzing the dependencies for com.h3xstream.test:demo-insecure-project
    [INFO] Syncing with the victims repository (based on the atom feed)
    [INFO] Downloading: https://github.com/victims/victims-cve-db/commits.atom
    [INFO] Already to the latest version.
    [ERROR] org.apache.struts:struts2-core is vulnerable to CVE-2014-0094
    [ERROR] org.apache.struts:struts2-core is vulnerable to CVE-2014-0112
    [ERROR] org.apache.struts:struts2-core is vulnerable to CVE-2014-0113
    [ERROR] org.apache.struts:struts2-core is vulnerable to CVE-2014-0116
    [ERROR] org.apache.struts:struts2-core is vulnerable to CVE-2014-7809
    [ERROR] commons-fileupload:commons-fileupload is vulnerable to CVE-2013-2186
    [ERROR] commons-fileupload:commons-fileupload is vulnerable to CVE-2014-0050
    [ERROR] com.thoughtworks.xstream:xstream is vulnerable to CVE-2013-7285
    [INFO] ------------------------------------------------------------------------
    [INFO] BUILD SUCCESS
    [INFO] ------------------------------------------------------------------------
    [INFO] Total time: 2.200 s
    [INFO] Finished at: 2015-11-03T22:30:48-05:00
    [INFO] Final Memory: 13M/194M
    [INFO] ------------------------------------------------------------------------

## Licenses

 - [versions-maven-plugin](http://www.mojohaus.org/versions-maven-plugin/) : [Apache Software License](http://www.mojohaus.org/versions-maven-plugin/license.html)
 - [victims-cve-db](https://github.com/victims/victims-cve-db/) : [Creative Commons](https://creativecommons.org/licenses/by-sa/4.0/) / [Affero General Public License](https://github.com/victims/victims-cve-db/blob/master/LICENSE)
