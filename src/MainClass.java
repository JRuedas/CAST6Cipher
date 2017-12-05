
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.math3.stat.descriptive.moment.Kurtosis;
import org.apache.commons.math3.stat.descriptive.moment.Skewness;
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

    private static int sampleNumber = 10;
    private static int experimentsNumber = 3;

    private final static double PRECISION = 0.90;

    private static void startExperiment(int length) {
        int[] histogram;
        List<Double> calculatedMeans = null;
        List<Double> calculatedStandardDeviation = null;

        double experimentAccuracy = 1.0;

        do {
            if (experimentAccuracy < PRECISION) {
                sampleNumber *= 2;
            }

            // Length of maximum changes of hamming distance
            calculatedMeans = new ArrayList<>();
            calculatedStandardDeviation = new ArrayList<>();

            for (int i = 0; i < experimentsNumber; i++) {
                histogram = new int[length];

                int hammingDistance;
                for (int j = sampleNumber; j > 0; j--) {

                    if (length == 128) {
                        hammingDistance = experimentChangingMessage();
                    } else {
                        hammingDistance = experimentChangingKey();
                    }

                    if (hammingDistance != 0) {
                        histogram[hammingDistance - 1]++;
                    } else {
                        System.out.println("Algo falla con hamming");
                    }
                }

                double mean = mean(histogram);
                calculatedMeans.add(mean);
                calculatedStandardDeviation.add(standardDeviation(histogram, mean));
            }

            double totalMean = experimentValuesMean(calculatedMeans);
            double totalStandardDeviation = experimentValuesMean(calculatedStandardDeviation);

            experimentAccuracy = calculateExperimentAccuracy(totalMean, totalStandardDeviation, calculatedMeans, calculatedStandardDeviation);
        } while (experimentAccuracy < PRECISION);

        //Pintar histograma con desviaciones estandar y medias calculadas
        System.out.println("Se ha alcanzado la precision esperada");
    }

    private static int experimentChangingMessage() {
        // 256 bits key long -> 32 byte long
        byte[] key = generateRandomBitSequence(256);
        // 128 bits message long -> 16 byte long
        byte[] message = generateRandomBitSequence(128);

        byte[] cipherText = cipherMessage(key, message);

        byte[] similarMessage = generateSimilarSequence(message);

        byte[] newCipherText = cipherMessage(key, similarMessage);

        return hammingDistance(cipherText, newCipherText);
    }

    private static int experimentChangingKey() {
        // 256 bits key long -> 32 byte long
        byte[] key = generateRandomBitSequence(256);
        // 128 bits message long -> 16 byte long
        byte[] message = generateRandomBitSequence(128);

        byte[] cipherText = cipherMessage(key, message);

        byte[] similarKey = generateSimilarSequence(key);

        byte[] newCipherText = cipherMessage(similarKey, message);

        return hammingDistance(cipherText, newCipherText);
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

        return ((sequence[selectedByte] >> bitPosition) & 0x01) == 1;
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

        for (int i = 0; i < sequence1.length * 8; i++) {
            if (bitValue(sequence1, i) != bitValue(sequence2, i)) {
                hammingDistance++;
            }
        }
        return hammingDistance;
    }

    private static double mean(int[] histogram) {
        double mean = 0.0;

        for (int i = 0; i < histogram.length; i++) {
            mean += histogram[i];
        }
        return mean / sampleNumber;
    }

    private static double standardDeviation(int[] histogram, double mean) {
        double numerator = 0.0;

        for (int i = 0; i < histogram.length; i++) {
            numerator += Math.pow(histogram[i] - mean, 2);
        }

        return Math.sqrt(numerator / sampleNumber);
    }

    public static double median(int[] histogram) {
        int[] sortedHistogram = new int[histogram.length];
        System.arraycopy(histogram, 0, sortedHistogram, 0, histogram.length);

        int middle = sortedHistogram.length / 2;
        if (sortedHistogram.length % 2 == 1) {
            return sortedHistogram[middle];
        } else {
            return (sortedHistogram[middle - 1] + sortedHistogram[middle]) / 2.0;
        }
    }

    public static List<Integer> mode(int[] histogram) {
        List<Integer> modes = new ArrayList<>();
        Map<Integer, Integer> countMap = new HashMap<>();

        int max = -1;
        for (int number : histogram) {
            int count = 0;

            if (countMap.containsKey(number)) {
                count = countMap.get(number) + 1;
            } else {
                count = 1;
            }

            countMap.put(number, count);

            if (count > max) {
                max = count;
            }
        }

        for (Map.Entry<Integer, Integer> tuple : countMap.entrySet()) {
            if (tuple.getValue() == max) {
                modes.add(tuple.getKey());
            }
        }

        return modes;
    }

    public static double kurtosis(int[] histogram) {
        double[] histogramAux = new double[histogram.length];
        for (int i = 0; i < histogram.length; i++) {
            histogramAux[i] = histogram[i];
        }

        return new Kurtosis().evaluate(histogramAux, 0, histogramAux.length);
    }

    public static double skewness(int[] histogram) {
        double[] histogramAux = new double[histogram.length];
        for (int i = 0; i < histogram.length; i++) {
            histogramAux[i] = histogram[i];
        }
        return new Skewness().evaluate(histogramAux, 0, histogramAux.length);
    }

    private static double experimentValuesMean(List<Double> values) {
        double total = 0.0;

        for (double value : values) {
            total += value;
        }
        return total / values.size();
    }

    private static double calculateExperimentAccuracy(double totalMean, double totalStandardDeviation, List<Double> calculatedMeans, List<Double> calculatedStandardDeviation) {
        double r = 0.0;
        double d = 0.0;

        for (double mean : calculatedMeans) {
            r += (mean - totalMean);
        }
        r /= totalMean;

        for (double standardDeviation : calculatedStandardDeviation) {
            d += (standardDeviation - totalStandardDeviation);
        }
        d /= totalStandardDeviation;

        return Math.max(r, d);
    }

    public static void main(String[] args) {
        engine = new CAST6Engine();
        cipher = new PaddedBufferedBlockCipher(engine);
        randomGenerator = new SecureRandom();

        //startExperiment(128);
        //startExperiment(256);
        //experimentChangingMessage();
        //experimentChangingKey();
        // TESTS
        //totalResultsRandomNumber();
        //testGenerateRandomSequence();
        //testGenerateSimilarSequence();
        //testHamming();
        //testHammingHard()
        //testMean();
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

    private static void testHammingHard() {
        for (int i = 0; i < 10000000; i++) {
            int hamming = experimentChangingMessage();
            if (hamming == 0) {
                System.out.println("Algo falla con hamming, iteracion: " + i);
            }

            if (i % 1000000 == 0) {
                System.out.println("500000 mas");
            }
        }
    }

    private static void testMean() {
        int[] test = {3, 1, 7, 1, 6, 81, 6, 23, 62};
        System.out.println(mean(test));
    }
}
