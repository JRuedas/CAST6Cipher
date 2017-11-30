
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.BitSet;
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
    private static SecureRandom randomGenerator;

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

    /**
     * Generates random bits for given input [0,byteLength)
     *
     * @param byteLength 16 for 128 bits (block length -> message length)
     * and 32 for 256 bits (key length)
     * @return
     */
    private static byte[] generateRandomBitSequence(int bitLength) {
        byte bytes [] = new byte[bitLength/8];
        randomGenerator.nextBytes(bytes);
        return bytes;
    }

    /**
     * Generates random number in range [0-maxExclusive)
     * @param maxExclusive
     * @return 
     */
    private static int generateRandomNumber(int maxExclusive) {
        return randomGenerator.nextInt(maxExclusive);
    }

    public static void main(String[] args) {
        engine = new CAST6Engine();
        cipher = new PaddedBufferedBlockCipher(engine);
        randomGenerator = new SecureRandom();

        // 256 bits key length
        byte[] key = generateRandomBitSequence(256);
        // 128 bits message length
        byte[] message = generateRandomBitSequence(128);
        cipherMessage(key, message);
        
        // Complemento 1 bit del mensaje y vuelvo a cifrar
        BitSet bitSet = BitSet.valueOf(message);
        int bitToChange = generateRandomNumber(32);
        bitSet.flip(bitToChange);
        byte [] message2 = bitSet.toByteArray();

        cipherMessage(key, message2);
    }
}
