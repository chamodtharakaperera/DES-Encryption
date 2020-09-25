import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class DESEncryption {
    public static void encryptDecrypt(String key, int cipherMode, File in, File out)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
            IOException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        FileInputStream fis = new FileInputStream(in);
        FileOutputStream fos = new FileOutputStream(out);

        DESKeySpec desKeySpec = new DESKeySpec(key.getBytes());

        SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = skf.generateSecret(desKeySpec);

        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");

        byte[] ivBytes = new byte[8];
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        if (cipherMode == Cipher.ENCRYPT_MODE) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey,iv,SecureRandom.getInstance("SHA1PRNG"));
            CipherInputStream cis = new CipherInputStream(fis, cipher);
            write(cis, fos);

        } else if (cipherMode == Cipher.DECRYPT_MODE) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey,iv,SecureRandom.getInstance("SHA1PRNG"));
            CipherOutputStream cos = new CipherOutputStream(fos, cipher);
        }
    }

    private static void write(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[64];
        int numOfBytesRead;
        while ((numOfBytesRead = in.read(buffer)) != -1) {
            out.write(buffer, 0, numOfBytesRead);
        }
        out.close();
        out.close();
    }

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        File plainText = new File("C:\\Users\\charm\\Desktop\\AES\\test.txt");
        File encrypted = new File("C:\\Users\\charm\\Desktop\\AES\\encrypted.txt");
        File decrypted = new File("C:\\Users\\charm\\Desktop\\AES\\decrypted.txt");

        /*To enable Encrypt Mode
        try {
            encryptDecrypt("12345678", Cipher.ENCRYPT_MODE, plainText, encrypted);
            System.out.println("Encryption Completed");
         */

        /*To enable Decrypt Mode
        try {
            encryptDecrypt("12345678", Cipher.DECRYPT_MODE, encrypted, decrypted);
            System.out.println("Decryption Completed");
         */

        try {
            encryptDecrypt("12345678", Cipher.DECRYPT_MODE, encrypted, decrypted);
            System.out.println("Decryption Completed");
        } catch (InvalidKeySpecException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IOException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

    }

}
