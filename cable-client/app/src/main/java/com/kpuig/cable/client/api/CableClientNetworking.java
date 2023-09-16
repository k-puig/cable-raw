package com.kpuig.cable.client.api;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

// Handles sending data to the server via processing requests
public class CableClientNetworking {
    private Socket serverSocket;
    

    public CableClientNetworking(String domain, int port) throws UnknownHostException, IOException {
        this.serverSocket = new Socket(domain, port);
    }

    public void start() {

    }
}
