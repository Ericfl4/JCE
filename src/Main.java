import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;


public class Main {
    public static void main(String[] args) throws IOException {


        /*
        System.out.println("Ejercicio 1");
        UtilitatsXifrar utilitatsXifrar = new UtilitatsXifrar();


        System.out.println("Ej 1.5:");
        SecretKey skey5 = utilitatsXifrar.keygenKeyGeneration(256);

        String mensaje5 = "Manolo cabezabolo";
        byte[] mensajeEnBytes5 = mensaje5.getBytes("UTF8");

        byte[] mensajeEncriptado5 = utilitatsXifrar.encryptData(skey5, mensajeEnBytes5);
        byte[] mensajeDesencriptado5 = utilitatsXifrar.decryptData(skey5, mensajeEncriptado5);

        String newMensaje5 = new String(mensajeDesencriptado5,"UTF8");

        System.out.println(newMensaje5);
        System.out.println("La key de este ejercicio es: "+skey5.toString()+"(Ej 1.7)\n");

        System.out.println("Ej 1,6:");

        SecretKey skey6 = utilitatsXifrar.passwordKeyGeneration("Hola",256);
        SecretKey skey8 = utilitatsXifrar.passwordKeyGeneration("pepe",256);

        String mensaje6 = "Andres callate un mes";
        byte[] mensajeEnBytes6 = mensaje6.getBytes("UTF8");

        byte[] mensajeEncriptado6 = utilitatsXifrar.encryptData(skey6, mensajeEnBytes6);
        byte[] mensajeDesencriptado6 = utilitatsXifrar.decryptData(skey6, mensajeEncriptado6);
        byte[] mensajeDesencriptado8 = utilitatsXifrar.decryptData(skey8, mensajeEncriptado6);



        String newMensaje6 = new String(mensajeDesencriptado6,"UTF8");

        System.out.println(newMensaje6);
        System.out.println("La key de este ejercicio es: "+skey6.toString()+"(Ej 1.7)\n");

        System.out.println("Ej 1.8: Error BadPaddingException");
        */

        System.out.println("Ejercicio 2");

        UtilitatsXifrar utilitatsXifrar = new UtilitatsXifrar();

        Path path = Paths.get("textamagat.crypt");
        byte[] textamagat = Files.readAllBytes(path);

        File f = new File("clausA4.txt");
        FileReader fr = new FileReader(f);
        BufferedReader br = new BufferedReader(fr);
        String line = br.readLine();
        while(line != null ) {
            SecretKey skey = utilitatsXifrar.passwordKeyGeneration(line,128);
            byte[] textoByte = utilitatsXifrar.decryptData(skey,textamagat);
            if (textoByte!=null){
                System.out.println(line);
                String text = new String(textoByte,"UTF8");
                System.out.println(text);
            }
            line = br.readLine();
        }

    }
}