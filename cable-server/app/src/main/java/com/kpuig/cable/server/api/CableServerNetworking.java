package com.kpuig.cable.server.api;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.List;

import javax.annotation.Nonnull;

public class CableServerNetworking {
    /*
     * BEGIN CLASS DEFINITIONS
     */

    // This class only exists to accept clients
    private class ClientAcceptThread extends Thread {
        private CableServerRequestQueue requestQueue;
        private List<ClientProcessThread> clientProcesses;
        private ServerSocket serverSocket;

        public ClientAcceptThread(ServerSocket serverSocket, CableServerRequestQueue requestQueue) {
            this.serverSocket = serverSocket;
            this.clientProcesses = new LinkedList<>();
            this.requestQueue = requestQueue;
        }

        @Override
        public void run() {
            while (true) {
                Socket clientSocket;

                try {
                    clientSocket = serverSocket.accept();
                } catch (SocketTimeoutException e) {
                    e.printStackTrace();
                    System.err.println("Continuing server socket thread");
                    continue;
                } catch (IOException e) {
                    e.printStackTrace();
                    return;
                }

                ClientProcessThread processThread = new ClientProcessThread(clientSocket);
                clientProcesses.add(processThread);
                processThread.start();
            }
        }
    }

    // This class will be created per client
    // Each thread will have an initial handshake process
    // Upon a successful handshake, it will continually add requests to the queue
    private class ClientProcessThread extends Thread {
        private CableClient client;
        private Socket clientSocket;

        public ClientProcessThread(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            /* Handshake */
            // Send pubkey to client


            // Await client pubkey

            // Generate random bytes and encrypt with client key, then send to client

            // Await server-pubkey-encrypted message

            // Decrypt message and compare with original message, continue if matched

            
            // Continual process
            while (true) {
                return;
            }
        }
    }

    /*
     * END CLASS DEFINITIONS
     */

    private final String assymetricKeyAlgo = "RSA";

    private KeyPair encryptionKeyPair;
    private ServerSocket serverSocket;
    private List<CableServerRequest> requests;

    public CableServerNetworking(int port) throws IOException, NoSuchAlgorithmException {
        this.serverSocket = new ServerSocket(port);
        serverSocket.setSoTimeout(10 * 1000); // 10 seconds

        this.requests = new LinkedList<>();

        // Create pubkey/privkey pair
        SecureRandom random = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(assymetricKeyAlgo);
        keyPairGenerator.initialize(2048, random);
        encryptionKeyPair = keyPairGenerator.generateKeyPair();
    }

    // Guarantee: all requests will be valid and secure
    // All returned lists may have zero items
    // Return will be non-null
    @Nonnull
    public List<CableServerRequest> getAndClearRequests() {
        List<CableServerRequest> returned = requests;
        requests = new LinkedList<>();
        return returned;
    }
}
