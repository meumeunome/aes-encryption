import org.apache.commons.codec.binary.Hex;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Encryptor {

    private String encryptedMessage;
    private String iv;

    /**
     * Encryptor constructor. Params: message to be encrypted, 256-bit key (32
     * characters long). Returns Object containing the encrypted message and the IV
     * used.
     */
    public Encryptor(String message, String key) {
        RandomString randomString = new RandomString(16);

        iv = randomString.nextString();

        try {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

            encryptedMessage = new String(Hex.encodeHex(cipher.doFinal(message.getBytes())));
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException
                | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    /**
     * Returns message encrypted in Hex String format.
     */
    public String getEncryptedMessage() {
        return encryptedMessage;
    }

    /**
     * Returns IV in 16 characters long Alphanumeric String format. A simple
     * getBytes() can extract its byte[].
     */
    public String getIV() {
        return iv;
    }
}
