
import java.util.Arrays;
import java.util.Random;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.CAST6Engine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author Jonat
 */
public class MainClass {

    private static BlockCipher engine;
    private static BufferedBlockCipher cipher;

    private static String cipherMessage(byte[] key, byte[] message) {

        cipher.init(true, new KeyParameter(key));

        byte[] cipherText = new byte[cipher.getOutputSize(message.length)];

        int outputLen = cipher.processBytes(message, 0, message.length, cipherText, 0);

        try {
            cipher.doFinal(cipherText, outputLen);

            System.out.println(Arrays.toString(cipherText));
        } catch (CryptoException ce) {
            System.err.println(ce);
            System.exit(1);
        }
        return Arrays.toString(cipherText);
    }

    private static byte[] changeRandomBit(byte[] text) {
        int randomByte = randomNumber(0, text.length);
        int randomBit = randomNumber(0, 8);
        boolean bitValue = checkBitValue(text[randomByte], randomBit);
        
        text[randomByte] = (bitValue ? 
                            (byte) (text[randomByte] & ~(1 << randomBit)) :
                            (byte) (text[randomByte] | (1 << randomBit)));
        return text;
    }

    private static int randomNumber(int low, int high) {
        Random r = new Random();
        return r.nextInt(high - low) + low;
    }

    // True if bit = 1, false if = 0
    public final static Boolean checkBitValue(byte randomByte, int bitPosition) {
        return (randomByte & (1 << bitPosition)) != 0;
    }

    public static void main(String[] args) {
        engine = new CAST6Engine();
        cipher = new PaddedBufferedBlockCipher(engine);
        
        String keyString = "Hola";
        String messageString = "Cifrado";
        
        byte [] key = keyString.getBytes();
        byte [] message = messageString.getBytes();
        
        cipherMessage(key, message);
        
        key = changeRandomBit(key);
        
        cipherMessage(key, message);
    }
}
