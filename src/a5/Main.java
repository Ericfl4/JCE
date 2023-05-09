package a5;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.Scanner;


public class Main {
    public static void main(String[] args) throws IOException {

        Scanner scanner = new Scanner(System.in);
        UtilitatsXifrar utilitatsXifrar = new UtilitatsXifrar();

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
    }
}