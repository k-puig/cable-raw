package com.kpuig.cable.client.api;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

public class CableClient {
    Socket serverSocket;

    public CableClient(String domain, int port) throws UnknownHostException, IOException {
        this.serverSocket = new Socket(domain, port);
    }

    public void start() {
        
    }
}
