import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Decrypt {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("Enter base-64 econded ciphertext, IV, and secret key, separated by <Enter> key: ");
        Scanner scanner = new Scanner(System.in);

        byte[] ciphertext = DatatypeConverter.parseBase64Binary(scanner.nextLine());
        byte[] iv = DatatypeConverter.parseBase64Binary(scanner.nextLine());
        byte[] secret_key = DatatypeConverter.parseBase64Binary(scanner.nextLine());

        IvParameterSpec receiver_iv = new IvParameterSpec(iv);
        SecretKey receiver_secret = new SecretKeySpec(secret_key, "AES");

        Cipher receiver_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        receiver_cipher.init(Cipher.DECRYPT_MODE, receiver_secret, receiver_iv);

        String plaintext = new String(receiver_cipher.doFinal(ciphertext), "UTF-8");

        System.out.println(plaintext);
    }
}