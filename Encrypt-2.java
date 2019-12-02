import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;


public class Encrypt {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter message to encrypt: ");
        String plaintext = scanner.nextLine();

        // Create Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        SecretKey aesKey = keygen.generateKey();

        // Encrypt Message
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));
        byte[] iv = cipher.getIV();
        byte[] secret = aesKey.getEncoded();

        System.out.println(DatatypeConverter.printBase64Binary(ciphertext));
        System.out.println(DatatypeConverter.printBase64Binary(iv));
        System.out.println(DatatypeConverter.printBase64Binary(secret));
    }
}