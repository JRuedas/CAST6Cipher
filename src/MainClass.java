
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
    private final static int NUMBER_OF_EXPERIMENTS = 100;

    private static int[] messsagesHistogram;
    private static int[] keysHistogram;

    private static void experimentChangingMessage() {
        // 256 bits key long -> 32 byte long
        byte[] key = generateRandomBitSequence(256);
        // 128 bits message long -> 16 byte long
        byte[] message = generateRandomBitSequence(128);

        byte[] cipherText = cipherMessage(key, message);

        byte[] similarMessage = generateSimilarSequence(message);

        byte[] newCipherText = cipherMessage(key, similarMessage);

        int hammingDistance = hammingDistance(cipherText, newCipherText);
        messsagesHistogram[hammingDistance]++;
    }

    private static void experimentChangingKey() {
        // 256 bits key long -> 32 byte long
        byte[] key = generateRandomBitSequence(256);
        // 128 bits message long -> 16 byte long
        byte[] message = generateRandomBitSequence(128);

        byte[] cipherText = cipherMessage(key, message);

        byte[] similarKey = generateSimilarSequence(key);

        byte[] newCipherText = cipherMessage(similarKey, message);

        int hammingDistance = hammingDistance(cipherText, newCipherText);
        keysHistogram[hammingDistance]++;
    }

    private static byte[] cipherMessage(byte[] key, byte[] message) {
        cipher.init(true, new KeyParameter(key));

        byte[] cipherText = new byte[cipher.getOutputSize(message.length)];

        int outputLen = cipher.processBytes(message, 0, message.length, cipherText, 0);

        try {
            cipher.doFinal(cipherText, outputLen);
        } catch (CryptoException ce) {
            System.err.println(ce);
            System.exit(1);
        }
        return cipherText;
    }

    /**
     * Generates random bits for given input [0,byteLength)
     *
     * @param byteLength 16 for 128 bits (block length -> message length) and 32
     * for 256 bits (key length)
     * @return
     */
    private static byte[] generateRandomBitSequence(int bitLength) {
        SecureRandom randomGenerator = new SecureRandom();
        byte bytes[] = new byte[bitLength / 8];
        randomGenerator.nextBytes(bytes);
        return bytes;
    }

    /**
     * Generates random number in range [0-maxExclusive)
     *
     * @param maxExclusive
     * @return
     */
    private static int generateRandomBitNumber(int maxExclusive) {
        SecureRandom randomGenerator = new SecureRandom();
        return randomGenerator.nextInt(maxExclusive);
    }

    private static byte[] generateSimilarSequence(byte[] sequence) {
        byte[] similarSequence = new byte[sequence.length];
        System.arraycopy(sequence, 0, similarSequence, 0, sequence.length);

        int randomBit = generateRandomBitNumber(similarSequence.length * 8);

        boolean bitValue = bitValue(similarSequence, randomBit);

        return complementBit(similarSequence, randomBit, bitValue);
    }

    // True if bit = 1, false if = 0 
    public static boolean bitValue(byte[] sequence, int bit) {
        int selectedByte = bit / 8;
        // Position of this bit in a byte
        int bitPosition = bit % 8;

        return (sequence[selectedByte] >> bitPosition & 1) == 1;
    }

    public static byte[] complementBit(byte[] sequence, int bit, boolean bitValue) {
        // Get the index of the array for the byte with this bit
        int selectedByte = bit / 8;
        // Position of this bit in a byte
        int bitPosition = bit % 8;

        sequence[selectedByte] = (bitValue
                ? (byte) (sequence[selectedByte] & ~(1 << bitPosition))
                : (byte) (sequence[selectedByte] | (1 << bitPosition)));
        return sequence;
    }

    private static int hammingDistance(byte[] sequence1, byte[] sequence2) {
        int hammingDistance = 0;

        for (int i = 0; i < 8; i++) {
            if (bitValue(sequence1, i) != bitValue(sequence2, i)) {
                hammingDistance++;
            }
        }
        return hammingDistance;
    }
    
    private static int mean() {
        return 0;
    }

    public static void main(String[] args) {
        engine = new CAST6Engine();
        cipher = new PaddedBufferedBlockCipher(engine);
        messsagesHistogram = new int[128];
        keysHistogram = new int[256];

        for (int i = NUMBER_OF_EXPERIMENTS; i > 0; i--) {
            experimentChangingMessage();
        }

        for (int i = NUMBER_OF_EXPERIMENTS; i > 0; i--) {
            experimentChangingKey();
        }

        //experimentChangingMessage();
        //experimentChangingKey();
        // TESTS
        //totalResultsRandomNumber();
        //testGenerateRandomSequence();
        //testGenerateSimilarSequence();
        //testHamming();
    }

    private static void printBits(byte[] sequence) {
        String s1 = "";
        for (byte b : sequence) {
            s1 += String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0');
        }
        System.out.println(s1);
    }

    private static void totalResultsRandomNumber() {
        List<int[]> results = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            results.add(testGenerateRandomNumber());
        }

        int[] totalResults = new int[128];

        for (int[] result : results) {
            for (int i = 0; i < result.length; i++) {
                totalResults[i] += result[i];
            }
        }
        System.out.println(Arrays.toString(totalResults));
    }

    private static int[] testGenerateRandomNumber() {
        int[] results = new int[128];
        for (int i = 0; i < 100; i++) {
            results[generateRandomBitNumber(128)]++;
        }
        return results;
    }

    private static void testGenerateRandomSequence() {
        System.out.println("128 bits -> 16 Bytes -> Message");
        for (int i = 0; i < 50; i++) {
            byte[] test = generateRandomBitSequence(128);
            printBits(test);
        }

        System.out.println("\n256 bits -> 32 Bytes -> Keys");
        for (int i = 0; i < 50; i++) {
            byte[] test = generateRandomBitSequence(256);
            printBits(test);
        }
    }

    private static void testGenerateSimilarSequence() {
        byte[] sequence = generateRandomBitSequence(8);
        printBits(sequence);
        byte[] sequence2 = generateSimilarSequence(sequence);
        printBits(sequence2);
        System.out.println(Arrays.equals(sequence, sequence2));
    }

    private static void testHamming() {
        byte[] sequence = generateRandomBitSequence(8);
        printBits(sequence);
        byte[] sequence2 = generateSimilarSequence(sequence);
        printBits(sequence2);
        byte[] sequence3 = generateSimilarSequence(sequence2);
        printBits(sequence3);
        System.out.println(hammingDistance(sequence, sequence2));
        System.out.println(hammingDistance(sequence, sequence3));
        byte[] newSequence = generateRandomBitSequence(8);
        printBits(newSequence);
        System.out.println(hammingDistance(sequence, newSequence));
    }
}
