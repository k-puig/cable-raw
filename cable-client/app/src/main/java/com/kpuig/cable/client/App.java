/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package com.kpuig.cable.client;

import java.io.IOException;
import java.net.UnknownHostException;

import com.kpuig.cable.client.api.CableClient;

public class App {
    private CableClient client;

    public App(CableClient client) {
        this.client = client;
    }

    public void start() {
        client.start();
    }

    public static void main(String[] args) throws UnknownHostException, IOException {
        CableClient client = new CableClient("localhost", 5687);
        App app = new App(client);
        app.start();
    }
}
