package com.kpuig.cable.server.api;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import javax.annotation.Nonnull;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CableServerNetworking {
    /*
     * BEGIN CLASS DEFINITIONS
     */

    // This class only exists to accept clients
    // Only one thread will be instantiated
    private class ClientAcceptThread implements Runnable {
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
                Thread clientThread = new Thread(processThread);
                clientThread.start();
            }
        }
    }

    // This class will be created per client
    // Each thread will have an initial handshake process
    // Upon a successful handshake, it will continually add requests to the queue
    private class ClientProcessThread implements Runnable {
        private CableClient client;
        private Socket clientSocket;
        private KeyPair serverKeys;
        private Cipher rsaCipherEncrypt;
        private Cipher rsaCipherDecrypt;

        private PublicKey clientPubKey;
        private Cipher rsaClientEncrypt;

        private SecretKey aesEncryptionKey;

        public ClientProcessThread(Socket clientSocket, KeyPair serverKeys) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
            this.clientSocket = clientSocket;
            this.serverKeys = serverKeys;
            this.rsaCipherEncrypt = Cipher.getInstance(asymmetricKeyAlgo);
            this.rsaCipherDecrypt = Cipher.getInstance(asymmetricKeyAlgo);
            rsaCipherEncrypt.init(Cipher.ENCRYPT_MODE, serverKeys.getPublic());
            rsaCipherDecrypt.init(Cipher.DECRYPT_MODE, serverKeys.getPrivate());
        }

        @Override
        public void run() {
            /* Handshake */
            // Send pubkey to client
            byte[] serverPubKey = serverKeys.getPublic().getEncoded();
            try {
                clientSocket.getOutputStream().write(intToBytes(serverPubKey.length));
                clientSocket.getOutputStream().write(serverPubKey);
            } catch (IOException e) {
                e.printStackTrace();
                System.err.println("Failed to send server pubkey to client");
                return;
            }

            // Await client pubkey
            int nextNBytes = 0;
            byte[] clientPubKey;
            try {
                nextNBytes = bytesToInt(clientSocket.getInputStream().readNBytes(4));
                clientPubKey = clientSocket.getInputStream().readNBytes(nextNBytes);
            } catch (IOException e) {
                e.printStackTrace();
                System.err.println("Failed to receive client pubkey");
                return;
            }
            
            try {
                KeyFactory keyFactory = KeyFactory.getInstance(asymmetricKeyAlgo);
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPubKey);
                this.clientPubKey = keyFactory.generatePublic(keySpec);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
                System.err.println("Error converting encoded client pubkey");
                return;
            }

            // Create client pubkey cipher
            try {
                this.rsaClientEncrypt = Cipher.getInstance(asymmetricKeyAlgo);
                this.rsaClientEncrypt.init(Cipher.ENCRYPT_MODE, this.clientPubKey);
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
                e.printStackTrace();
                System.err.println("Failed to create cipher from given client pubkey");
                return;
            }

            // Generate random bytes and encrypt with client key, then send to client
            SecureRandom messageMaker = new SecureRandom();
            byte[] message = new byte[32];
            messageMaker.nextBytes(message);
            byte[] encryptedMessage;
            try {
                encryptedMessage = rsaClientEncrypt.doFinal(message);
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
                System.err.println("Error with encrypting the test message for client connection");
                return;
            }

            try {
                clientSocket.getOutputStream().write(intToBytes(encryptedMessage.length));
                clientSocket.getOutputStream().write(encryptedMessage);
            } catch (IOException e) {
                e.printStackTrace();
                System.err.println("Error sending encrypted message to client");
                return;
            }
            
            // Await server-pubkey-encrypted message
            byte[] clientEncryptedMessage;
            try {
                nextNBytes = bytesToInt(clientSocket.getInputStream().readNBytes(4));
                clientEncryptedMessage = clientSocket.getInputStream().readNBytes(nextNBytes);
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

            // Signal to client that pubkey exchange was successful
            byte[] successMessage = "PKACCEPTED".getBytes();
            try {
                successMessage = rsaClientEncrypt.doFinal(successMessage);
                clientSocket.getOutputStream().write(intToBytes(successMessage.length));
                clientSocket.getOutputStream().write(successMessage);
            } catch (IllegalBlockSizeException | BadPaddingException | IOException e) {
                e.printStackTrace();
                System.err.println("Against all odds after successful handshake, sending ACCEPTED signal failed");
                return;
            }

            // Generate IV and AES
            KeyGenerator keyGenerator;
            try {
                keyGenerator = KeyGenerator.getInstance(symmetricKeyAlgo);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                System.err.println("Error generating key generator instance for AES");
                return;
            }
            keyGenerator.init(symmetricKeyBits);
            this.aesEncryptionKey = keyGenerator.generateKey();
            byte[] aesKeyBytes = aesEncryptionKey.getEncoded();

            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[16];
            secureRandom.nextBytes(iv);
            IvParameterSpec ivParamSpec = new IvParameterSpec(iv);

            // Send IV and AES key
            try {
                clientSocket.getOutputStream().write(intToBytes(iv.length));
                clientSocket.getOutputStream().write(iv);
            } catch (IOException e) {
                e.printStackTrace();
                System.err.println("Error sending IV");
                return;
            }

            byte[][] splitAesKey = splitIntoNSizeChunks(aesEncryptionKey.getEncoded(), 24);
            try {
                for (int i = 0; i < splitAesKey.length; i++) {
                    splitAesKey[i] = rsaClientEncrypt.doFinal(splitAesKey[i]);
                }
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
                System.err.println("Error encrypting the AES key prior to sending");
            }

            try {
                clientSocket.getOutputStream().write(intToBytes(splitAesKey.length));
                for (byte[] bArr : splitAesKey) {
                    clientSocket.getOutputStream().write(intToBytes(bArr.length));
                    clientSocket.getOutputStream().write(bArr);
                }
            } catch (IOException e) {
                e.printStackTrace();
                System.err.println("Error in sending encoded AES key chunks");
                return;
            }

            // Generate hash of IV and AES key
            byte[] hashed;
            try {
                MessageDigest digest = MessageDigest.getInstance(hashAlgo);
                hashed = digest.digest(combinedByteArr(iv, aesKeyBytes));
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                System.err.println("Error hashing iv and aes key");
                return;
            }

            // Await hash of IV and AES key
            
            byte[] clientHash;
            try {
                nextNBytes = bytesToInt(clientSocket.getInputStream().readNBytes(4));
                clientHash = clientSocket.getInputStream().readNBytes(nextNBytes);
            } catch (IOException e) {
                e.printStackTrace();
                System.err.println("Error receiving IV and AES hash from client");
                return;
            }

            // Compare client hash with server hash
            if (hashed.length != clientHash.length) {
                System.err.println("Hash length mismatch. AES+IV exchange with client failed.");
                return;
            }
            for (int i = 0; i < hashed.length; i++) {
                if (hashed[i] != clientHash[i]) {
                    System.err.println("Mismatch at index " + i + " for hash equivalence check");
                    return;
                }
            }
            System.out.println("WEEEEE");

            // Await new or existing user credentials
            

            // Continue getting data from the client
            while (true) {
                return;
            }
        }
    }

    /*
     * END CLASS DEFINITIONS
     */

    private final String asymmetricKeyAlgo = "RSA";
    private final int asymmetricKeyBits = 2048;

    private final String symmetricKeyAlgo = "AES";
    private final int symmetricKeyBits = 256;

    private final String hashAlgo = "SHA-256";

    private KeyPair encryptionKeyPair;
    private ServerSocket serverSocket;
    private List<CableServerRequest> requests;

    public CableServerNetworking(int port) throws IOException, NoSuchAlgorithmException {
        this.serverSocket = new ServerSocket(port);
        serverSocket.setSoTimeout(10 * 1000); // 10 seconds

        this.requests = new LinkedList<>();

        // Create pubkey/privkey pair
        SecureRandom random = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(asymmetricKeyAlgo);
        keyPairGenerator.initialize(asymmetricKeyBits, random);
        encryptionKeyPair = keyPairGenerator.generateKeyPair();
    }

    public void start(CableServerRequestQueue requestQueue) {
        ClientAcceptThread acceptRunnable = new ClientAcceptThread(serverSocket, encryptionKeyPair, requestQueue);
        Thread acceptThread = new Thread(acceptRunnable);
        acceptThread.start();
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

    public static int bytesToInt(byte[] bytes) {
        assert(bytes.length == 4);
        return ByteBuffer.wrap(bytes).getInt();
    }

    public static byte[] intToBytes(int i) {
        byte[] bytes = ByteBuffer.allocate(4).putInt(i).array();
        return bytes;
    }

    public static byte[][] splitIntoNSizeChunks(byte[] data, int n) {
        int chunkCount = data.length / n;
        if (data.length % n > 0) {
            chunkCount++;
        }

        byte[][] splitData = new byte[chunkCount][];

        for (int i = 0; i < chunkCount; i++) {
            int start = i * n;
            List<Byte> byteList = new ArrayList<>();
            for (int j = start; j < Math.min(start + n, data.length); j++) {
                byteList.add(data[j - start]);
            }
            
            byte[] byteArray = new byte[byteList.size()];
            int byteI = 0;
            for (byte b : byteList) {
                byteArray[byteI++] = b;
            }
            splitData[i] = byteArray;
        }

        return splitData;
    }

    public static byte[] combine2DByteArr(byte[][] splitData) {
        int finalSize = 0;
        for (int i = 0; i < splitData.length; i++) {
            finalSize += splitData[i].length;
        }

        byte[] combinedData = new byte[finalSize];
        int cdIndex = 0;
        for (byte[] bArr : splitData) {
            for (byte b : bArr) {
                combinedData[cdIndex++] = b;
            }
        }

        return combinedData;
    }

    public static byte[] combinedByteArr(byte[] left, byte[] right) {
        byte[] result = new byte[left.length + right.length];

        for (int i = 0; i < left.length; i++) {
            result[i] = left[i];
        }
        for (int j = 0; j < right.length; j++) {
            result[j + left.length] = right[j];
        }

        return result;
    }
}
