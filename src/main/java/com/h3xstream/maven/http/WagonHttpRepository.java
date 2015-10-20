package com.h3xstream.maven.http;


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

import java.io.File;

public class WagonHttpRepository implements HttpRepository {
    private static final String URL_REPO = "https://github.com/victims/victims-cve-db/";
    private Repository rep;
    private Wagon w;
    private Log log;

    public WagonHttpRepository(Log log,WagonManager wagonManager) throws ConnectionException, AuthenticationException, WagonConfigurationException, UnsupportedProtocolException {
        this.log = log;
        this.rep = new Repository(URL_REPO, URL_REPO);
        this.w = wagonManager.getWagon(rep);

        w.connect(rep, wagonManager.getProxy(rep.getProtocol()));
    }

    @Override
    public void getFile(String path,File outFile) throws AuthorizationException, ResourceDoesNotExistException, TransferFailedException {
        log.info("Downloading: " + URL_REPO + path);
        w.get(path,outFile);
    }
}
