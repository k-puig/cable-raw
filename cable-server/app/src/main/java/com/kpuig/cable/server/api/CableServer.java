package com.kpuig.cable.server.api;

import java.io.IOException;

public class CableServer {
    CableServerNetworking networking;
    CableServerRequestQueue requestQueue;

    public CableServer(int port) throws IOException {
        this.networking = new CableServerNetworking(port);
        this.requestQueue = new CableServerRequestQueue();
    }

    // Initialize server socket thread and request processing thread
    public void start() {

    }
}
