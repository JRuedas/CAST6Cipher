
import java.util.Arrays;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.CAST6Engine;
import org.bouncycastle.crypto.modes.PaddedBlockCipher;
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

    private static void cipherMessage(String keyString, String messageString) {

        byte[] key = keyString.getBytes();
        byte[] message = messageString.getBytes();

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
    }

    public static void main(String[] args) {
        engine = new CAST6Engine();
        cipher = new PaddedBufferedBlockCipher(engine);
        
        cipherMessage(keyString, messageString);
    }
}
