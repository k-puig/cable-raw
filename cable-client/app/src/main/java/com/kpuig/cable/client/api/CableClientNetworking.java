package com.kpuig.cable.client.api;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

// Handles sending data to the server via processing requests
public class CableClientNetworking {
    private final String assymetricKeyAlgo = "RSA";

    private Socket serverSocket;
    private KeyPair encryptionKeyPair;
    

    public CableClientNetworking(String domain, int port) throws UnknownHostException, IOException, NoSuchAlgorithmException {
        this.serverSocket = new Socket(domain, port);

        // Create pubkey/privkey pair
        SecureRandom random = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(assymetricKeyAlgo);
        keyPairGenerator.initialize(2048, random);
        encryptionKeyPair = keyPairGenerator.generateKeyPair();
    }

    public void start() {
        // Await server pubkey

        // Send this pubkey

        // Await server encrypted test message

        // Decrypt and re-encryp test message, then send back to server

        // Await accept signal
    }
}
