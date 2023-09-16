package com.kpuig.cable.server.api;

import java.net.Socket;

// This is a successfully-connect client
public class CableClient {
    private String username;
    private int id;
    private Socket socket;
    
    public CableClient(String username, int id, Socket socket) {
        this.username = username;
        this.id = id; 
        this.socket = socket;
    }
}
