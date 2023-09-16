package com.kpuig.cable.client.api;

import java.io.IOException;
import java.net.UnknownHostException;

public class CableClient {
    CableClientNetworking clientNetworking;

    public CableClient(String domain, int port) throws UnknownHostException, IOException {
        this.clientNetworking = new CableClientNetworking(domain, port);
    }

    public void start() {
        
    }
}
