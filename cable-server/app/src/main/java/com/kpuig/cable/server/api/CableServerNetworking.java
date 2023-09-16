package com.kpuig.cable.server.api;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedList;
import java.util.List;

import javax.annotation.Nonnull;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CableServerNetworking {
    /*
     * BEGIN CLASS DEFINITIONS
     */

    // This class only exists to accept clients
    private class ClientAcceptThread extends Thread {
        private CableServerRequestQueue requestQueue;
        private List<ClientProcessThread> clientProcesses;
        private ServerSocket serverSocket;
        private KeyPair serverKeys;

        public ClientAcceptThread(ServerSocket serverSocket, KeyPair serverKeys, CableServerRequestQueue requestQueue) {
            this.serverSocket = serverSocket;
            this.serverKeys = serverKeys;
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

                ClientProcessThread processThread;
                try {
                    processThread = new ClientProcessThread(clientSocket, serverKeys);
                } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
                    e.printStackTrace();
                    System.err.println("Error when setting up encryption with the client");
                    return;
                }
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
        private KeyPair serverKeys;
        private Cipher rsaCipherEncrypt;
        private Cipher rsaCipherDecrypt;

        private PublicKey clientPubKey;

        public ClientProcessThread(Socket clientSocket, KeyPair serverKeys) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
            this.clientSocket = clientSocket;
            this.serverKeys = serverKeys;
            this.rsaCipherEncrypt = Cipher.getInstance(assymetricKeyAlgo);
            this.rsaCipherDecrypt = Cipher.getInstance(assymetricKeyAlgo);
            rsaCipherEncrypt.init(Cipher.ENCRYPT_MODE, serverKeys.getPublic());
            rsaCipherEncrypt.init(Cipher.DECRYPT_MODE, serverKeys.getPrivate());
        }

        @Override
        public void run() {
            /* Handshake */
            // Send pubkey to client
            byte[] serverPubKey = serverKeys.getPublic().getEncoded();
            try {
                clientSocket.getOutputStream().write(serverPubKey);
            } catch (IOException e) {
                e.printStackTrace();
                System.err.println("Failed to send server pubkey to client");
                return;
            }

            // Await client pubkey
            byte[] clientPubKey;
            try {
                clientPubKey = clientSocket.getInputStream().readAllBytes();
            } catch (IOException e) {
                e.printStackTrace();
                System.err.println("Failed to receive client pubkey");
                return;
            }
            
            try {
                KeyFactory keyFactory = KeyFactory.getInstance(assymetricKeyAlgo);
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPubKey);
                this.clientPubKey = keyFactory.generatePublic(keySpec);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
                System.err.println("Error converting encoded client pubkey");
            }

            // Generate random bytes and encrypt with client key, then send to client
            SecureRandom messageMaker = new SecureRandom();
            byte[] message = new byte[32];
            messageMaker.nextBytes(message);
            byte[] encryptedMessage;
            try {
                encryptedMessage = rsaCipherEncrypt.doFinal(message);
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
                System.err.println("Error with encrypting the test message for client connection");
                return;
            }

            try {
                clientSocket.getOutputStream().write(encryptedMessage);
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                System.err.println("Error sending encrypted message to client");
                return;
            }
            
            // Await server-pubkey-encrypted message
            byte[] clientEncryptedMessage;
            try {
                clientEncryptedMessage = clientSocket.getInputStream().readAllBytes();
            } catch (IOException e) {
                e.printStackTrace();
                System.err.println("Error receiving client encrypted message");
                return;
            }

            // Decrypt message and compare with original message, continue if matched
            byte[] clientDecryptedMessage;

            try {
                clientDecryptedMessage = rsaCipherDecrypt.doFinal(clientEncryptedMessage);
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
                System.err.println("Error decrypting the client's message");
                return;
            }

            
            if (message.length != clientDecryptedMessage.length) {
                System.err.println("Message length mismatch. Handshake with client failed.");
                return;
            }
            for (int i = 0; i < message.length; i++) {
                if (message[i] != clientDecryptedMessage[i]) {
                    System.err.println("Mismatch at index " + i + " for message equivalence check");
                    return;
                }
            }
            
            // Continue getting data from the client
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

    public void start(CableServerRequestQueue requestQueue) {

        ClientAcceptThread acceptThread = new ClientAcceptThread(serverSocket, encryptionKeyPair, requestQueue);
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
