package com.kpuig.cable.client.api;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

// Handles sending data to the server via processing requests
public class CableClientNetworking {
    private final String assymetricKeyAlgo = "RSA";

    private Socket serverSocket;
    private KeyPair encryptionKeyPair;
    private Cipher rsaCipherEncrypt;
    private Cipher rsaCipherDecrypt;

    private PublicKey serverPubKey;
    private Cipher rsaServerEncrypt;
    

    public CableClientNetworking(String domain, int port) throws UnknownHostException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        this.serverSocket = new Socket(domain, port);

        // Create pubkey/privkey pair
        SecureRandom random = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(assymetricKeyAlgo);
        keyPairGenerator.initialize(2048, random);
        encryptionKeyPair = keyPairGenerator.generateKeyPair();

        rsaCipherEncrypt = Cipher.getInstance(assymetricKeyAlgo);
        rsaCipherEncrypt.init(Cipher.ENCRYPT_MODE, encryptionKeyPair.getPublic());

        rsaCipherDecrypt = Cipher.getInstance(assymetricKeyAlgo);
        rsaCipherDecrypt.init(Cipher.DECRYPT_MODE, encryptionKeyPair.getPrivate());
    }

    public void start() throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        // Await server pubkey and create cipher
        byte[] serverPubkeyBytes = serverSocket.getInputStream().readAllBytes();
        KeyFactory keyFactory = KeyFactory.getInstance(assymetricKeyAlgo);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverPubkeyBytes);
        
        this.serverPubKey = keyFactory.generatePublic(keySpec);
        this.rsaServerEncrypt = Cipher.getInstance(assymetricKeyAlgo);
        rsaServerEncrypt.init(Cipher.ENCRYPT_MODE, serverPubKey);
        

        // Send this pubkey
        byte[] clientPubkeyBytes = encryptionKeyPair.getPublic().getEncoded();
        serverSocket.getOutputStream().write(clientPubkeyBytes);

        // Await server encrypted test message
        byte[] encryptedMessage = serverSocket.getInputStream().readAllBytes();

        // Decrypt and re-encrypt test message, then send back to server
        byte[] decryptedMessage = rsaCipherDecrypt.doFinal(encryptedMessage);
        byte[] serverEncryptedMessage = rsaServerEncrypt.doFinal(decryptedMessage);
        serverSocket.getOutputStream().write(serverEncryptedMessage);

        // Await accept signal
        byte[] encryptedAcceptSignal = serverSocket.getInputStream().readAllBytes();
        byte[] acceptSignal = rsaCipherDecrypt.doFinal(encryptedAcceptSignal);
        if (!new String(acceptSignal).equals("ACCEPT")) {
            throw new Error("Incorrect ACCEPT signal received: \"" + new String(acceptSignal) + "\"");
        }

        // Send credentials
    }
}
