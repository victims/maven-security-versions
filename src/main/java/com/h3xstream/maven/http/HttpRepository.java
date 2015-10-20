package com.h3xstream.maven.http;

import org.apache.maven.wagon.ResourceDoesNotExistException;
import org.apache.maven.wagon.TransferFailedException;
import org.apache.maven.wagon.authorization.AuthorizationException;

import java.io.File;
import java.io.IOException;

public interface HttpRepository {

    void getFile(String path,File output) throws AuthorizationException, ResourceDoesNotExistException, TransferFailedException, IOException;
}
