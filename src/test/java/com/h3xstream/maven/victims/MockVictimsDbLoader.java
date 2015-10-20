package com.h3xstream.maven.victims;


import com.h3xstream.maven.http.HttpRepository;
import org.apache.maven.plugin.logging.SystemStreamLog;
import org.apache.maven.wagon.ResourceDoesNotExistException;
import org.apache.maven.wagon.TransferFailedException;
import org.apache.maven.wagon.authorization.AuthorizationException;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import static org.mockito.Mockito.spy;

public class MockVictimsDbLoader {
    /**
     * @return An instance of VictimDbLoader
     */
    public static VictimsDbLoader createMock() {

        final SystemStreamLog log = new SystemStreamLog();
        try {
            VictimsDbLoader loader = spy(new VictimsDbLoader(log,null));
            loader.repo = new HttpRepository() {

                private static final String URL_REPO = "https://github.com/victims/victims-cve-db/";

                @Override
                public void getFile(String path, File output) throws AuthorizationException, ResourceDoesNotExistException, TransferFailedException, IOException {
                    log.info("Downloading: " + URL_REPO + path);
                    URL oracle = new URL(URL_REPO + path);
                    HttpURLConnection yc = (HttpURLConnection) oracle.openConnection();
                    InputStream in = yc.getInputStream();

                    if (!output.exists())
                        output.createNewFile();
                    FileOutputStream out = new FileOutputStream(output);

                    copyStream(in, out);
                }
            };

            return loader;
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize the VictimsDbLoader mock",e);
        }
    }

    private static void copyStream(InputStream input, OutputStream output) throws IOException
    {
        byte[] buffer = new byte[1024]; // Adjust if you want
        int bytesRead;
        while ((bytesRead = input.read(buffer)) != -1)
        {
            output.write(buffer, 0, bytesRead);
        }
    }
}
