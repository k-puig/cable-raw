package com.kpuig.cable.client.api;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CableClient {
    CableClientNetworking clientNetworking;

    public CableClient(String domain, int port) throws UnknownHostException, IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        this.clientNetworking = new CableClientNetworking(domain, port);
    }

    public void start() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
        clientNetworking.start();
    }
}
