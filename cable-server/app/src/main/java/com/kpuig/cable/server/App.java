/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package com.kpuig.cable.server;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import com.kpuig.cable.server.api.CableServer;

public class App {
    private CableServer server;

    public App(CableServer server) {
        this.server = server;
    }

    public void start() {
        server.start();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        CableServer server = new CableServer(5687);
        App app = new App(server);
        app.start();
    }
}
