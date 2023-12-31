/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package com.kpuig.cable.client;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.kpuig.cable.client.api.CableClient;

public class App {
    private CableClient client;

    public App(CableClient client) {
        this.client = client;
    }

    public void start() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
        client.start();
    }

    public static void main(String[] args) throws UnknownHostException, IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        CableClient client = new CableClient("localhost", 5687);
        App app = new App(client);
        app.start();
    }
}
