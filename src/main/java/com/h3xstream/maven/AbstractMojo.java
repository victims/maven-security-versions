package com.h3xstream.maven;

import org.apache.maven.artifact.manager.WagonManager;
import org.apache.maven.artifact.metadata.ArtifactMetadataSource;
import org.apache.maven.artifact.repository.ArtifactRepository;
import org.apache.maven.artifact.resolver.ArtifactResolver;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectBuilder;
import org.apache.maven.project.path.PathTranslator;
import org.apache.maven.settings.Settings;
import org.apache.maven.shared.dependency.graph.DependencyGraphBuilder;
import org.codehaus.mojo.versions.DisplayDependencyUpdatesMojo;
import org.codehaus.mojo.versions.api.DefaultVersionsHelper;
import org.codehaus.mojo.versions.api.VersionsHelper;

import java.util.List;

/**
 * This abstract class contains all the generic Maven component injected.
 * This huge list would otherwise clutter the main class.
 */
public class AbstractMojo extends DisplayDependencyUpdatesMojo {

    /**
     * The Maven Project.
     *
     * @parameter property="project"
     * @required
     * @readonly
     * @since 1.0-alpha-1
     */
    private MavenProject project;

    /**
     * @component
     * @since 1.0-alpha-1
     */
    protected org.apache.maven.artifact.factory.ArtifactFactory artifactFactory;

    /**
     * @component
     * @since 1.0-alpha-1
     */
    protected org.apache.maven.artifact.resolver.ArtifactResolver resolver;


    /**
     * The artifact metadata source to use.
     *
     * @component
     * @required
     * @readonly
     * @since 1.0-alpha-1
     */
    protected ArtifactMetadataSource artifactMetadataSource;

    /**
     * @parameter property="project.remoteArtifactRepositories"
     * @readonly
     * @since 1.0-alpha-3
     */
    protected List remoteArtifactRepositories;

    /**
     * @parameter property="project.pluginArtifactRepositories"
     * @readonly
     * @since 1.0-alpha-3
     */
    protected List remotePluginRepositories;

    /**
     * @parameter property="localRepository"
     * @readonly
     * @since 1.0-alpha-1
     */
    protected ArtifactRepository localRepository;

    /**
     * @component
     * @since 1.0-alpha-3
     */
    protected WagonManager wagonManager;

    /**
     * @parameter property="settings"
     * @readonly
     * @since 1.0-alpha-3
     */
    protected Settings settings;

    /**
     * settings.xml's server id for the URL.
     * This is used when wagon needs extra authentication information.
     *
     * @parameter property="maven.version.rules.serverId" default-value="serverId";
     * @since 1.0-alpha-3
     */
    private String serverId;

    /**
     * The Wagon URI of a ruleSet file containing the rules that control how to compare version numbers.
     *
     * @parameter property="${maven.version.rules}"
     * @since 1.0-alpha-3
     */
    private String rulesUri;

    /**
     * Controls whether a backup pom should be created (default is true).
     *
     * @parameter property="generateBackupPoms"
     * @since 1.0-alpha-3
     */
    private Boolean generateBackupPoms;

    /**
     * Whether to allow snapshots when searching for the latest version of an artifact.
     *
     * @parameter property="allowSnapshots" default-value="false"
     * @since 1.0-alpha-1
     */
    protected Boolean allowSnapshots;

    /**
     * Our versions helper.
     */
    private VersionsHelper helper;

    /**
     * The Maven Session.
     *
     * @parameter property="session"
     * @required
     * @readonly
     * @since 1.0-alpha-1
     */
    protected MavenSession session;

    /**
     * @component
     */
    protected PathTranslator pathTranslator;

    /**
     * @component
     */
    protected ArtifactResolver artifactResolver;

    /**
     * The dependency tree builder to use.
     * @component
     */
    protected DependencyGraphBuilder dependencyGraphBuilder;

    @Override
    public MavenProject getProject() {
        return project;
    }

    @Override
    public void setProject(MavenProject project) {
        this.project = project;
    }

    public VersionsHelper getHelper() throws MojoExecutionException
    {
        if ( helper == null )
        {
            helper = new DefaultVersionsHelper( artifactFactory, artifactResolver, artifactMetadataSource,
                    remoteArtifactRepositories, remotePluginRepositories, localRepository,
                    wagonManager, settings, serverId, rulesUri, getLog(), session,
                    pathTranslator );
        }
        return helper;
    }

}
