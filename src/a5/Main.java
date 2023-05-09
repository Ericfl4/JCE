package a5;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Scanner;


public class Main {
    public static void main(String[] args) throws Exception {

        Scanner scanner = new Scanner(System.in);
        UtilitatsXifrar utilitatsXifrar = new UtilitatsXifrar();


        //Ex 1:
        /*

        KeyPair keyPair = utilitatsXifrar.randomGenerate(1024);
        System.out.println("Dime el mensaje");
        String mensaje = scanner.nextLine();

        byte[] mensajeEnBytes = mensaje.getBytes("UTF8");

        byte[] mensajeEncriptado = utilitatsXifrar.encryptData(keyPair.getPublic(), mensajeEnBytes);
        byte[] mensajeDesencriptado = utilitatsXifrar.decryptData(keyPair.getPrivate(), mensajeEncriptado);

        String newMensaje = new String(mensajeDesencriptado,"UTF8");
        System.out.println("El mensaje es: "+newMensaje);
        System.out.println("La clave publica es: "+keyPair.getPublic().toString());
        System.out.println("La clave privada es: "+keyPair.getPrivate().toString());
        */

        //Ex 2:
        KeyStore keyStore = utilitatsXifrar.loadKeyStore("C:/Users/ericf/mykeystore.jks","1Manzanar");
        System.out.println("Tipo de keystore: " + keyStore.getType());
        System.out.println("Cantidad de keys en la keystore: " + keyStore.size());

        System.out.println("Alias de todas las keys en la keystore:");
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println(alias);
        }

        Enumeration<String> aliases2 = keyStore.aliases();
        String alias = aliases2.nextElement();
        String pas = "1Manzanar";
        char[] pasChar = pas.toCharArray();
        Key algorithm = keyStore.getKey(alias, pasChar);
        System.out.println("Llave: "+alias+
                ", Certificado: "+keyStore.getCertificate(alias)+
                ", Algoritomo de cifrado: "+algorithm);


        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection("1Manzanar".toCharArray());
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);

        keyStore.setEntry("mykey3", secretKeyEntry, protParam);


        PublicKey pk = utilitatsXifrar.getPublicKey(keyStore, "mykey", "1Manzanar");
        System.out.println("Public key:");
        System.out.println(pk.toString());





        KeyPairGenerator keyGen2 = KeyPairGenerator.getInstance("RSA");
        keyGen2.initialize(2048);
        KeyPair keyPair2 = keyGen2.generateKeyPair();

        PrivateKey privateKey = keyPair2.getPrivate();
        PublicKey publicKey = keyPair2.getPublic();

        byte[] data = "Hello world".getBytes();

        byte[] signature = utilitatsXifrar.signData(data, privateKey);

        System.out.println(signature.toString());

        boolean verified = utilitatsXifrar.validateSignature(data, signature, publicKey);

        if (verified) {
            System.out.println("La firma "+signature+" es válida");
        } else {
            System.out.println("La firma "+signature+" no es válida");
        }


        String saludo = "Hola mariposa";
        byte[][] encryptWD = utilitatsXifrar.encryptWrappedData(saludo.getBytes(),publicKey);
        byte[] decryptWD = utilitatsXifrar.decryptWrappedData(encryptWD, privateKey);
        System.out.println(decryptWD.toString());


    }
}