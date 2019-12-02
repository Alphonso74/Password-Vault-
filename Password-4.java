import java.awt.*;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Hashtable;
import java.util.Objects;
import java.util.Random;
import java.util.Scanner;
import java.util.stream.Collectors;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.stream.*;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.lang.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.lang.*;

import java.io.Console;

//alldecrypt is all the keys
//decrypt is for decrypting master pass
//depasswordvault has all information needed to decrypt passwords
//email gives id, user, but encrypted pass
//key idk
//master stores master
//password vault stores password
public class Password {

    public static void main(String[] args)  throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        Scanner reader = new Scanner(System.in);


        String id = "", user = "", pass = "";
        int length = 8;
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz" + "0123456789";
        boolean isId = false;

        File file = new File("passwordVault.txt");
        FileWriter fw = new FileWriter(file,true);


        if (!file.exists()) {
            file.createNewFile();
            System.out.println("File created");
        }

        Scanner scanner = new Scanner(file);
        // 2options


        String master = "password";

        File mastertxt = new File("master.txt");
        FileWriter mtxt = new FileWriter(mastertxt,true);


        File mr = new File("mr.txt");
        FileWriter mrtxt = new FileWriter(mr,true);


        File decrypttxt = new File("decrypt.txt");
        FileWriter dtxt = new FileWriter(decrypttxt,true);


        File depassword = new File("depasswordvault.txt");
        FileWriter depasstxt = new FileWriter(depassword, true);


        File all = new File("alldecrypt.txt");
        FileWriter alld = new FileWriter(all, true);

        File key = new File("key.txt");
        FileWriter keyd = new FileWriter(key, true);

///////////////////////////////////

        Scanner text3 = new Scanner(new File("decrypt.txt"));
        Scanner text4 = new Scanner(new File ("master.txt"));

        String plai = " ";
        if(text3.hasNextLine() && text4.hasNextLine()) {
            String ivvy = text3.nextLine();
            String secrett = text3.nextLine();
            String demaster = text4.nextLine();
            byte[] cipmaster = DatatypeConverter.parseBase64Binary(demaster);
            byte[] ive = DatatypeConverter.parseBase64Binary(ivvy);
            byte[] secret_key = DatatypeConverter.parseBase64Binary(secrett);
            IvParameterSpec receiver_iv = new IvParameterSpec(ive);
            SecretKey receiver_secret = new SecretKeySpec(secret_key, "AES");
            Cipher receiver_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            receiver_cipher.init(Cipher.DECRYPT_MODE, receiver_secret, receiver_iv);
            plai = new String(receiver_cipher.doFinal(cipmaster), "UTF-8");
        }





        //     System.out.println(demaster);
        //   System.out.println(ivvy);
        //  System.out.println(secrett);


        // System.out.println(plai);




        ////////////////////////////
        String mas = "";
        System.out.println("enter master pass");


        ///////

        Console cons;
        char[] passwd;
        if ((cons = System.console()) != null &&
                (passwd = cons.readPassword("[%s]", "Password:")) != null) {
            mas = String.valueOf(passwd);

            java.util.Arrays.fill(passwd, ' ');
        }


        if(mastertxt.length() != 0)
        {

            Scanner text2 = new Scanner(new File("mr.txt"));
            master = text2.nextLine();

        }
        else
        {
            master = "password";
        }









        if(!mas.equals(master) && !mas.equals(plai))
        {
            System.out.println("Invalid");
            System.exit(0);
        }


        Scanner ye = new Scanner(System.in);
        if(depassword.length() != 0 &&  mas.equals(plai)) {
            System.out.println("Do you want to send your friend the keys for decryption? (yes / no)");
            String finale = ye.nextLine();
            if(finale.equals("yes"))
            {

                System.out.println("Enter master password:");

                Console cons2;
                char[] passwd2;
                String mas2 ="";
                if ((cons2 = System.console()) != null &&
                        (passwd2 = cons2.readPassword("[%s]", "Password:")) != null) {
                    mas2 = String.valueOf(passwd2);

                    java.util.Arrays.fill(passwd2, ' ');
                }


                //create master txt first
                //check if it's already empty
                //if empty then set it to passsword
                //else set mas to w/e is in there already

                if(mastertxt.length() != 0)
                {

                    Scanner text2 = new Scanner(new File("mr.txt"));
                    master = text2.nextLine();

                }
                else
                {
                    master = "password";
                }


                if(!mas2.equals(master) && !mas2.equals(plai))
                {
                    System.out.println("Invalid");
                    System.exit(0);
                }

                String cert = "Qmt5014";


                System.out.println("Enter name of CACert");
                String certAns = reader.nextLine();

                if(!cert.equals(certAns))
                {
                    System.exit(0);
                }






                Scanner text6 = new Scanner(new File ("depasswordvault.txt"));

                if(text6.hasNextLine()) {
                    key.delete();
                    key = new File("key.txt");
                    keyd = new FileWriter(key, false);


                    while (text6.hasNextLine())
                    {

                        String secrett = " ";
                        secrett = text6.nextLine();
                        secrett = text6.nextLine();
                        secrett = text6.nextLine();

                        String boki = secrett;

                        keyd.write(boki + "\n");


                    }
                    keyd.close();
                }
            }
        }

        if(depassword.length() != 0 &&  mas.equals(plai))
        {
            System.out.println("Do you want the your passwords decrypted into alldecrypt.txt for yourself? (yes / no)");
            String finale = ye.nextLine();

            if(finale.equals("yes"))
            {

                System.out.println("Enter master password:");

                Console cons3;
                char[] passwd3;
                String mas3 ="";
                if ((cons3 = System.console()) != null &&
                        (passwd3 = cons3.readPassword("[%s]", "Password:")) != null) {
                    mas3 = String.valueOf(passwd3);

                    java.util.Arrays.fill(passwd3, ' ');
                }


                //create master txt first
                //check if it's already empty
                //if empty then set it to passsword
                //else set mas to w/e is in there already

                if(mastertxt.length() != 0)
                {

                    Scanner text2 = new Scanner(new File("mr.txt"));
                    master = text2.nextLine();

                }
                else
                {
                    master = "password";
                }


                if(!mas3.equals(master) && !mas3.equals(plai))
                {
                    System.out.println("Invalid");
                    System.exit(0);
                }

                Scanner text5 = new Scanner(new File ("depasswordvault.txt"));


                if(text5.hasNextLine())
                {

                    all.delete();

                    all = new File("alldecrypt.txt");
                    alld = new FileWriter(all, false);
                    while (text5.hasNextLine())
                    {
                        String demaster = text5.nextLine();
                        String ivvy = text5.nextLine();
                        String secrett = text5.nextLine();

                        byte[] cipmaster = DatatypeConverter.parseBase64Binary(demaster);
                        byte[] ive = DatatypeConverter.parseBase64Binary(ivvy);
                        byte[] secret_key = DatatypeConverter.parseBase64Binary(secrett);
                        IvParameterSpec receiver_iv = new IvParameterSpec(ive);
                        SecretKey receiver_secret = new SecretKeySpec(secret_key, "AES");
                        Cipher receiver_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        receiver_cipher.init(Cipher.DECRYPT_MODE, receiver_secret, receiver_iv);
                        String  plaintext = new String(receiver_cipher.doFinal(cipmaster), "UTF-8");

                        alld.write(plaintext);
                        alld.write("\n");



                        //   System.out.println(plaintext);
                    }


                    alld.close();

                    ////


                }

            }

        }



        if(mas.equals(master) || mas.equals(plai))
        {
            System.out.println("Do you want to change master password? (yes / no)");
            String change = reader.nextLine();

            if(change.equals("yes"))
            {
                System.out.println("enter new password");



                String newMasterPass = "";



                ///////

                Console cons7;
                char[] passwd7;
                if ((cons7 = System.console()) != null &&
                        (passwd7 = cons7.readPassword("[%s]", "Password:")) != null) {
                    newMasterPass = String.valueOf(passwd7);

                    java.util.Arrays.fill(passwd7, ' ');
                }


                mastertxt.delete();
                mastertxt = new File("master.txt");
                mtxt = new FileWriter(mastertxt,false);



                KeyGenerator keygen = KeyGenerator.getInstance("AES");
                SecretKey aesKey = keygen.generateKey();

                // Encrypt Message
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, aesKey);
                byte[] ciphertext = cipher.doFinal(newMasterPass.getBytes("UTF-8"));
                byte[] iv = cipher.getIV();
                byte[] secret = aesKey.getEncoded();

                newMasterPass = (DatatypeConverter.printBase64Binary(ciphertext));

                decrypttxt.delete();
                decrypttxt = new File("decrypt.txt");
                dtxt = new FileWriter(decrypttxt,false);

                dtxt.write(DatatypeConverter.printBase64Binary(iv));
                dtxt.write("\n");
                dtxt.write(DatatypeConverter.printBase64Binary(secret));
                dtxt.close();



                mtxt.write(newMasterPass);
                mtxt.close();
                /////////////////////


         //       File mr = new File("mr.txt");
           //     FileWriter mrtxt = new FileWriter(mrtxt,true);






                System.out.println("Use old master password for the remainder of this session");




            }


        }
        mr.delete();
        mr = new File("mr.txt");
        Scanner tez = new Scanner(new File("master.txt"));


        mr = new File("mr.txt");
        FileWriter fw3 = new FileWriter(mr, false);

        while (tez.hasNextLine()) {
            fw3.write(tez.nextLine() + "\n");
        }


        fw3.close();






        System.out.println("Want to make another entry, or want to change something (entry / change)");

        String input = reader.nextLine();
        if(input.equals("entry"))
        {
            System.out.println("Enter master password:");

            Console cons4;
            char[] passwd4;
            String mas4 ="";
            if ((cons4 = System.console()) != null &&
                    (passwd4 = cons4.readPassword("[%s]", "Password:")) != null) {
                mas4 = String.valueOf(passwd4);

                java.util.Arrays.fill(passwd4, ' ');
            }


            //create master txt first
            //check if it's already empty
            //if empty then set it to passsword
            //else set mas to w/e is in there already

            if(mastertxt.length() != 0)
            {

                Scanner text2 = new Scanner(new File("mr.txt"));
                master = text2.nextLine();

            }
            else
            {
                master = "password";
            }


            if(!mas4.equals(master) && !mas4.equals(plai))
            {
                System.out.println("Invalid");
                System.exit(0);
            }


            System.out.println("Enter Id");
            id = reader.nextLine();
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////finish////////////////////////////////////////////////////////
            while (scanner.hasNextLine())
            {
                String a = scanner.nextLine();

                if(a.contains(id))
                {
                    isId = true;
                    System.out.println("Sorry this id already exist.");
                    System.exit(0);
                    System.out.println("Do you want to change password? (yes / no)");
                    input = reader.nextLine();
                    if(input.equals("no"))
                    {
                        System.out.println("Do you want us to send a text file (yes / no)");
                        input = reader.nextLine();
                        if(input.equals("yes"))
                        {

                            String cert = "Qmt5014";


                            System.out.println("Enter name of CACert");
                            String certAns = reader.nextLine();

                            if(!cert.equals(certAns))
                            {
                                System.exit(0);
                            }





                            Scanner text = new Scanner(new File("passwordVault.txt"));


                            File filed = new File("email.txt");


                            FileWriter fw2 = new FileWriter(filed, false);

                            while (text.hasNextLine()) {
                                fw2.write(text.nextLine() + "\n");
                            }


                            fw2.close();

                            System.out.println("Successfully sent!  ");


                            System.exit(0);
                        }
                        else
                        {
                            System.exit(0);

                        }


                    }


                    if(input.equals("yes"))
                    {
                        System.out.println("Enter master password:");

                        Console cons5;
                        char[] passwd5;
                        String mas5 ="";
                        if ((cons5 = System.console()) != null &&
                                (passwd5 = cons5.readPassword("[%s]", "Password:")) != null) {
                            mas5 = String.valueOf(passwd5);

                            java.util.Arrays.fill(passwd5, ' ');
                        }


                        //create master txt first
                        //check if it's already empty
                        //if empty then set it to passsword
                        //else set mas to w/e is in there already

                        if(mastertxt.length() != 0)
                        {

                            Scanner text2 = new Scanner(new File("mr.txt"));
                            master = text2.nextLine();

                        }
                        else
                        {
                            master = "password";
                        }


                        if(!mas5.equals(master) && !mas5.equals(plai))
                        {
                            System.out.println("Invalid");
                            System.exit(0);
                        }


                        System.out.println("Enter username");
                        user = reader.nextLine();

                        System.out.println("Enter old pass");
                        String oldPass = reader.nextLine();



                        System.out.println("Enter new password");
                        pass = reader.nextLine();



                        String name = "passwordVault.txt";


                        String oldString = a;

                        String newString =   id + "\t|\t" + user + "\t|\t" + pass;
                        ///////////////////////////////////////////////////////////////////////////////////////////////////////

                        fw.write(newString);



                        fw.close();

                        removeLineFromFile(name, a);
                        fw.close();
                        break;

                    }

                }

            }//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////finish :3/////////////////////////////


            if(!isId)
            {
                System.out.println("Enter username");
                user = reader.nextLine();

                System.out.println("Do you want us to make password? (yes / no)");
                input = reader.nextLine();

                if(input.equals("yes"))
                {
                        ///////////////////////////////////////////////////////////////////////

                    SecureRandom random = SecureRandom.getInstanceStrong();
                    pass = random + "";
                   // pass = new Random().ints(length, 0, chars.length()).mapToObj(i -> "" + chars.charAt(i)).collect(Collectors.joining());



                    //////////////////////////////////////////////////////////////////////////////

                    KeyGenerator keygen = KeyGenerator.getInstance("AES");
                    SecretKey aesKey = keygen.generateKey();

                    // Encrypt Message
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, aesKey);
                    byte[] ciphertext = cipher.doFinal(pass.getBytes("UTF-8"));
                    byte[] iv = cipher.getIV();
                    byte[] secret = aesKey.getEncoded();

                    String cippass = DatatypeConverter.printBase64Binary(ciphertext);
                    String ivv = DatatypeConverter.printBase64Binary(iv);
                    String secrett = DatatypeConverter.printBase64Binary(secret);




                    depasstxt.write(DatatypeConverter.printBase64Binary(ciphertext));
                    depasstxt.write("\n");
                    depasstxt.write(DatatypeConverter.printBase64Binary(iv));
                    depasstxt.write("\n");
                    depasstxt.write(secrett);
                    depasstxt.write("\n");
                    depasstxt.close();


                    /*                                                                                                                                                                                             */
                    fw.write(id + "\t|\t" + user + "\t|\t" + cippass +  "\n");
                }
                else
                {
                    System.out.println("Enter password");
                    pass = reader.nextLine();
                    KeyGenerator keygen = KeyGenerator.getInstance("AES");
                    SecretKey aesKey = keygen.generateKey();

                    // Encrypt Message
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, aesKey);
                    byte[] ciphertext = cipher.doFinal(pass.getBytes("UTF-8"));
                    byte[] iv = cipher.getIV();
                    byte[] secret = aesKey.getEncoded();

                    String cippass = DatatypeConverter.printBase64Binary(ciphertext);
                    String ivv = DatatypeConverter.printBase64Binary(iv);
                    String secrett = DatatypeConverter.printBase64Binary(secret);

                    depasstxt.write(DatatypeConverter.printBase64Binary(ciphertext));
                    depasstxt.write("\n");
                    depasstxt.write(DatatypeConverter.printBase64Binary(iv));
                    depasstxt.write("\n");
                    depasstxt.write(secrett);
                    depasstxt.write("\n");
                    depasstxt.close();


                    fw.write(id + "\t|\t" + user + "\t|\t" + cippass +  "\n");

                }



                fw.close();


            }


            System.out.println("Do you want a text file to send for a friend? (yes / no)");
            input =reader.nextLine();

            if(input.equals("yes"))
            {
                System.out.println("Enter master password:");

                Console cons6;
                char[] passwd6;
                String mas6 = "";
                if ((cons6 = System.console()) != null &&
                        (passwd6 = cons6.readPassword("[%s]", "Password:")) != null) {
                    mas6 = String.valueOf(passwd6);

                    java.util.Arrays.fill(passwd6, ' ');
                }


                //create master txt first
                //check if it's already empty
                //if empty then set it to passsword
                //else set mas to w/e is in there already

                if(mastertxt.length() != 0)
                {

                    Scanner text2 = new Scanner(new File("mr.txt"));
                    master = text2.nextLine();

                }
                else
                {
                    master = "password";
                }


                if(!mas6.equals(master) && !mas6.equals(plai))
                {
                    System.out.println("Invalid");
                    System.exit(0);
                }

                String cert = "Qmt5014";


                System.out.println("Enter name of CACert");
                String certAns = reader.nextLine();

                if(!cert.equals(certAns))
                {
                    System.exit(0);
                }







                Scanner text = new Scanner(new File("passwordVault.txt"));



                File filed = new File("email.txt");


                FileWriter fw2 = new FileWriter(filed,false);

                while (text.hasNextLine())
                {
                    fw2.write(text.nextLine() + "\n");
                }



                fw2.close();

                System.out.println("Successfully sent!");
            }







            System.exit(0);
        }

        if(!input.equals("change"))
        {
            System.out.println("Error bad input");
            System.exit(0);
        }



        scanner = new Scanner(file);





        System.out.println("Do you want a text file for yourself of the vault (yes / no)");
        input =reader.nextLine();

        if(input.equals("yes"))
        {
            Scanner text = new Scanner(new File("passwordVault.txt"));



            File filed = new File("email.txt");


            FileWriter fw2 = new FileWriter(filed,false);

            while (text.hasNextLine())
            {
                fw2.write(text.nextLine() + "\n");
            }



            fw2.close();

            System.out.println("Successfully sent!");
        }





        if(input.equals("no"))
        {
            while (scanner.hasNextLine())
            {
                String a = scanner.nextLine();

                if(a.contains(id))
                {


                    System.out.println("Do you want to change password? (yes / no)");
                    input = reader.nextLine();
                    if(input.equals("no"))
                    {
                        System.out.println("Do you want us to send a text file (yes / no)");
                        input = reader.nextLine();



                        if(input.equals("yes"))
                        {

                            Scanner text = new Scanner(new File("passwordVault.txt"));


                            File filed = new File("email.txt");


                            FileWriter fw2 = new FileWriter(filed, false);

                            while (text.hasNextLine()) {
                                fw2.write(text.nextLine() + "\n");
                            }


                            fw2.close();

                            System.out.println("Successfully sent!");


                            break;
                        }
                        else
                        {
                            break;
                        }


                    }

                    while (scanner.hasNextLine())
                    {
                        String aa = scanner.nextLine();

                        if(aa.contains(id))
                        {
                            isId = true;

                            System.out.println("Are you sure u want to change password? (yes / no)");
                            input = reader.nextLine();
                            if(input.equals("no"))
                            {
                                System.out.println("Do you want us to send a text file (yes / no)");
                                input = reader.nextLine();
                                if(input.equals("yes"))
                                {
                                    Scanner text = new Scanner(new File("passwordVault.txt"));


                                    File filed = new File("email.txt");


                                    FileWriter fw2 = new FileWriter(filed, false);

                                    while (text.hasNextLine()) {
                                        fw2.write(text.nextLine() + "\n");
                                    }


                                    fw2.close();

                                    System.out.println("Successfully sent!");

                                    System.exit(0);
                                }
                                else
                                {
                                    System.exit(0);

                                }


                            }


                            if(input.equals("yes"))
                            {
                                System.out.println("enter id");
                                id = reader.nextLine();

                                System.out.println("Enter username");
                                user = reader.nextLine();

                                System.out.println("Enter old pass");
                                String oldPass = reader.nextLine();



                                System.out.println("Enter new password");
                                pass = reader.nextLine();



                                String name = "passwordVault.txt";


                                KeyGenerator keygen = KeyGenerator.getInstance("AES");
                                SecretKey aesKey = keygen.generateKey();

                                // Encrypt Message
                                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                                cipher.init(Cipher.ENCRYPT_MODE, aesKey);
                                byte[] ciphertext = cipher.doFinal(pass.getBytes("UTF-8"));
                                byte[] iv = cipher.getIV();
                                byte[] secret = aesKey.getEncoded();

                                String cippass = DatatypeConverter.printBase64Binary(ciphertext);
                                String secrett = DatatypeConverter.printBase64Binary(secret);

                                depasstxt.write(DatatypeConverter.printBase64Binary(ciphertext));
                                depasstxt.write("\n");
                                depasstxt.write(DatatypeConverter.printBase64Binary(iv));
                                depasstxt.write("\n");
                                depasstxt.write(secrett);
                                depasstxt.write("\n");
                                depasstxt.close();




                                String newString = "\n" + id + "\t|\t" + user + "\t|\t" + cippass;
                                ///////////////////////////////////////////////////////////////////////////////////////////////////////

                                fw.write(newString);



                                fw.close();

                                removeLineFromFile(name, id + "\t|\t" + user + "\t|\t" + oldPass);
                                fw.close();
                                System.exit(0);

                            }

                        }

                    }

                }

            }





        }





    }

    public static void removeLineFromFile(String file, String lineToRemove) {

        try {

            File inFile = new File(file);

            if (!inFile.isFile()) {
                System.out.println("Parameter is not an existing file");
                return;
            }

            //Construct the new file that will later be renamed to the original filename.
            File tempFile = new File(inFile.getAbsolutePath() + ".tmp");

            BufferedReader br = new BufferedReader(new FileReader(file));
            PrintWriter pw = new PrintWriter(new FileWriter(tempFile));

            String line = null;

            //Read from the original file and write to the new
            //unless content matches data to be removed.
            while ((line = br.readLine()) != null) {

                if (!line.trim().equals(lineToRemove)) {

                    pw.println(line);
                    pw.flush();
                }
            }
            pw.close();
            br.close();

            //Delete the original file
            if (!inFile.delete()) {
                // System.out.println("Could not delete file");
                return;
            }

            //Rename the new file to the filename the original file had.
            if (!tempFile.renameTo(inFile))
                System.out.println("Could not rename file");

        }
        catch (FileNotFoundException ex) {
            ex.printStackTrace();
        }
        catch (IOException ex) {
            ex.printStackTrace();
        }
    }
}