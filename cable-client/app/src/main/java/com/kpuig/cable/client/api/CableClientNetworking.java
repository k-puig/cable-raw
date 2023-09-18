package com.kpuig.cable.client.api;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
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
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

// Handles sending data to the server via processing requests
public class CableClientNetworking {
    private final String assymetricKeyAlgo = "RSA";
    private static final String hashAlgo = "SHA-256";

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
        // Connect
        this.serverSocket.setSoTimeout(10 * 1000); // 10 seconds
        
        // Await server pubkey and create cipher
        int nextNBytes = bytesToInt(serverSocket.getInputStream().readNBytes(4));
        byte[] serverPubkeyBytes = serverSocket.getInputStream().readNBytes(nextNBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(assymetricKeyAlgo);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverPubkeyBytes);
        
        this.serverPubKey = keyFactory.generatePublic(keySpec);
        this.rsaServerEncrypt = Cipher.getInstance(assymetricKeyAlgo);
        rsaServerEncrypt.init(Cipher.ENCRYPT_MODE, serverPubKey);
        
        // Send this pubkey
        byte[] clientPubkeyBytes = encryptionKeyPair.getPublic().getEncoded();
        serverSocket.getOutputStream().write(intToBytes(clientPubkeyBytes.length));
        serverSocket.getOutputStream().write(clientPubkeyBytes);

        // Await server encrypted test message
        nextNBytes = bytesToInt(serverSocket.getInputStream().readNBytes(4));
        byte[] encryptedMessage = serverSocket.getInputStream().readNBytes(nextNBytes);

        // Decrypt and re-encrypt test message, then send back to server
        byte[] decryptedMessage = rsaCipherDecrypt.doFinal(encryptedMessage);
        byte[] serverEncryptedMessage = rsaServerEncrypt.doFinal(decryptedMessage);
        serverSocket.getOutputStream().write(intToBytes(serverEncryptedMessage.length));
        serverSocket.getOutputStream().write(serverEncryptedMessage);

        // Await accept signal
        nextNBytes = bytesToInt(serverSocket.getInputStream().readNBytes(4));
        byte[] encryptedAcceptSignal = serverSocket.getInputStream().readNBytes(nextNBytes);
        byte[] acceptSignal = rsaCipherDecrypt.doFinal(encryptedAcceptSignal);
        if (!new String(acceptSignal).equals("PKACCEPTED")) {
            throw new Error("Incorrect ACCEPTED signal received: \"" + new String(acceptSignal) + "\"");
        }

        // Await AES key + IV
        nextNBytes = bytesToInt(serverSocket.getInputStream().readNBytes(4));
        byte[] iv = serverSocket.getInputStream().readNBytes(nextNBytes);
        int splitAesChunkCount = bytesToInt(serverSocket.getInputStream().readNBytes(4));
        byte[][] splitAesKeyBytes = new byte[splitAesChunkCount][];
        for (int i = 0; i < splitAesChunkCount; i++) {
            nextNBytes = bytesToInt(serverSocket.getInputStream().readNBytes(4));
            byte[] encryptedAesKeyChunk = serverSocket.getInputStream().readNBytes(nextNBytes);
            byte[] decryptedAesKeyChunk = rsaCipherDecrypt.doFinal(encryptedAesKeyChunk);
            splitAesKeyBytes[i] = decryptedAesKeyChunk;
        }
        byte[] aesKeyBytes = combine2DByteArr(splitAesKeyBytes);

        // Send back the SHA-256 hash of the AES key + IV
        MessageDigest digest = MessageDigest.getInstance(hashAlgo);
        byte[] hashed = digest.digest(combinedByteArr(iv, aesKeyBytes));
        serverSocket.getOutputStream().write(intToBytes(hashed.length));
        serverSocket.getOutputStream().write(hashed);

        System.out.println("FUYCK YEAH BABYY WOOOOOO");

        // Send credentials
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
