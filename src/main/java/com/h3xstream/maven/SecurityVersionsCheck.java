package com.h3xstream.maven;

import com.h3xstream.maven.tpl.ReportModel;
import com.h3xstream.maven.tpl.VulnerableLibrary;
import com.h3xstream.maven.victims.CveVulnerability;
import com.h3xstream.maven.victims.VictimsDbLoader;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.ArtifactUtils;
import org.apache.maven.artifact.resolver.filter.ArtifactFilter;
import org.apache.maven.artifact.versioning.ArtifactVersion;
import org.apache.maven.artifact.versioning.InvalidVersionSpecificationException;
import org.apache.maven.model.Dependency;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.apache.maven.shared.artifact.filter.ScopeArtifactFilter;
import org.apache.maven.shared.dependency.graph.DependencyGraphBuilderException;
import org.apache.maven.shared.dependency.graph.DependencyNode;
import org.codehaus.mojo.versions.DisplayDependencyUpdatesMojo;
import org.codehaus.mojo.versions.api.ArtifactVersions;
import org.codehaus.mojo.versions.api.UpdateScope;
import org.codehaus.mojo.versions.utils.DependencyComparator;
import org.apache.maven.artifact.metadata.ArtifactMetadataRetrievalException;
import org.codehaus.plexus.util.StringUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 *
 * @goal check
 * @requiresProject true
 * @requiresDirectInvocation false
 */
public class SecurityVersionsCheck extends AbstractMojo {

    /**
     * @parameter property="sec.updateRepo" defaultValue="false"
     */
    private Boolean updateRepository = Boolean.FALSE;
    private VictimsDbLoader victimDb;

    public void execute() throws MojoExecutionException, MojoFailureException {
        //Only execute this mojo once, on the very last project in the reactor
        if(reactorProjects != null) {
            final int size = reactorProjects.size();
            MavenProject lastProject = (MavenProject) reactorProjects.get(size - 1);
            if (lastProject != getProject()) {
                return;
            }
        }

        MavenProject project = getProject();

        victimDb = new VictimsDbLoader(getLog(),wagonManager);
        victimDb.loadRepository();

        DependencyNode rootNode;
        try {
            rootNode = dependencyGraphBuilder.buildDependencyGraph( project, createResolvingArtifactFilter() );

        } catch (DependencyGraphBuilderException e) {
            getLog().error("Unable to build the complete dependency graph.");
            throw new MojoFailureException("Unable to build the complete dependency graph.",e);
        }

        //Collect the vulnerabilities
        List<VulnerableLibrary> vulnerableLibraries = new ArrayList<VulnerableLibrary>();
        visitNode(rootNode,0,vulnerableLibraries);

        displayCommandLine(vulnerableLibraries);

        try {
            File targetDir = new File(getProject().getBuild().getDirectory());
            if(!targetDir.exists()) targetDir.mkdir();

            FileOutputStream out = new FileOutputStream(new File(getProject().getBuild().getDirectory(), "vulnerable_dependencies.html"));

            exportToHtml(vulnerableLibraries, out);

        } catch (FileNotFoundException e) {
            throw new MojoFailureException("Unable to write the HTML report.",e);
        } catch (IOException e) {
            throw new MojoFailureException("Unable to write the HTML report.",e);
        } catch (TemplateException e) {
            throw new MojoFailureException("Unable generate the HTML report using the template.",e);
        }

    }

    private void visitNode(DependencyNode baseNode,int level,List<VulnerableLibrary> vulnerabilities) {
        Artifact a = baseNode.getArtifact();

        //getLog().info(StringUtils.repeat("   ",level)+" -> "+a.getGroupId()+":"+a.getArtifactId()+":"+a.getVersion());

        List<CveVulnerability> cves = victimDb.search(a.getGroupId(), a.getArtifactId(), a.getVersion());

        if(cves.size() > 0) {
            vulnerabilities.add(new VulnerableLibrary(a, cves, getHierarchyChain(baseNode)));
        }

        for (DependencyNode childNode : baseNode.getChildren()) {
            visitNode(childNode, level + 1, vulnerabilities);
        }
    }

    private List<Artifact> getHierarchyChain(DependencyNode baseNode) {
        List<Artifact> chain = new ArrayList<Artifact>();

        DependencyNode node = baseNode;
        while((node = node.getParent()) != null) {
            chain.add(node.getArtifact());
        }
        return chain;
    }

    public void displayCommandLine(List<VulnerableLibrary> libraries) {
        if(!libraries.isEmpty()) {
            for(VulnerableLibrary lib : libraries) {
                Artifact a = lib.getArtifact();
                for(CveVulnerability vuln : lib.getVulnerabilities()) {
                    getLog().error(a.getGroupId() + ":" + a.getArtifactId() + " is vulnerable to CVE-" + vuln.getCveId());
                }
            }
        }
    }

    public void exportToHtml(List<VulnerableLibrary> libraries,OutputStream out) throws IOException, TemplateException {
        PrintWriter pw = new PrintWriter(out);
        /*
        MustacheFactory mf = new DefaultMustacheFactory();
        Mustache mustache = mf.compile("victims_tpl/vulnerable_dependencies.html");
        mustache.execute(pw, new ReportModel(vulnerabilities)).flush();
        */

        Configuration cfg = new Configuration();
        cfg.setClassForTemplateLoading(this.getClass(), "/");
        Template tpl = cfg.getTemplate("/victims_tpl/vulnerable_dependencies.html");

        Map<String,Object> ctxData = new HashMap<String,Object>();
        ctxData.put("libraries",libraries);

        tpl.process(ctxData, new OutputStreamWriter(out));
    }

    /**
     * Gets the artifact filter to use when resolving the dependency tree.
     *
     * @return the artifact filter
     */
    private ArtifactFilter createResolvingArtifactFilter()
    {
        return new ArtifactFilter() {
            @Override
            public boolean include(Artifact artifact) {
                return true;
            }
        };
    }

}
