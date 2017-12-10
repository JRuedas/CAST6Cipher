
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.math3.stat.descriptive.moment.Kurtosis;
import org.apache.commons.math3.stat.descriptive.moment.Mean;
import org.apache.commons.math3.stat.descriptive.moment.Skewness;
import org.apache.commons.math3.stat.descriptive.moment.StandardDeviation;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CreationHelper;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author Jonatan Ruedas Mora s100270
 */
public class Experiment {

    private static Provider bc;
    private static SecureRandom randomGenerator;
    private static final String KEY_ALGO = "CAST6";
    private static final String CIPHER_ALGO = "CAST6/ECB/NOPADDING";

    private static int sampleNumber = 25;
    private static int experimentsNumber = 3;

    private final static double PRECISION = 0.2;

    /**
     * Main function
     *
     * @param args
     */
    public static void main(String[] args) {
        bc = new BouncyCastleProvider();
        randomGenerator = new SecureRandom();

        startExperiment(128);
        startExperiment(256);

        // TESTS
//        totalResultsRandomNumber();
//        testGenerateRandomSequence();
//        testGenerateSimilarSequence();
//        testHamming();
//        testHammingHard();
//        testMeanAndSTD();
//        testMode();
//        testMedian();
//        test1CAST6();
//        test2CAST6();
//        test3CAST6();
    }

    /**
     * Executes different experiments depending on the given length
     *
     * @param length
     */
    private static void startExperiment(int length) {
        int[] histogram;
        int[] hammingDistances;
        List<Double> calculatedMeans = null;
        List<Double> calculatedStandardDeviation = null;
        List<Double> calculatedMedians = null;
        List<Double> calculatedModes = null;
        List<Double> calculatedKurtosis = null;
        List<Double> calculatedSkewness = null;

        double experimentAccuracy = 0.0;

        do {
            if (PRECISION < experimentAccuracy) {
                sampleNumber *= 2;
            }

            // Length of maximum changes of hamming distance
            calculatedMeans = new ArrayList<>();
            calculatedStandardDeviation = new ArrayList<>();
            List<int[]> histogramList = new ArrayList<>();
            calculatedMedians = new ArrayList<>();;
            calculatedModes = new ArrayList<>();;
            calculatedKurtosis = new ArrayList<>();;
            calculatedSkewness = new ArrayList<>();;

            for (int i = 0; i < experimentsNumber; i++) {
                histogram = new int[128];
                hammingDistances = new int[sampleNumber];

                int hammingDistance;
                for (int j = 0; j < sampleNumber; j++) {

                    if (length == 128) {
                        hammingDistance = experimentChangingMessage();
                    } else {
                        hammingDistance = experimentChangingKey();
                    }

                    if (hammingDistance != 0) {
                        hammingDistances[j] = hammingDistance;
                        histogram[hammingDistance - 1]++;
                    }
                }

                double mean = mean(hammingDistances);
                calculatedMeans.add(mean);
                calculatedStandardDeviation.add(standardDeviation(hammingDistances, mean));
                calculatedMedians.add(median(hammingDistances));
                List<Integer> modesAux = mode(hammingDistances);

                for (Integer integer : modesAux) {
                    calculatedModes.add((double) integer);
                }
                calculatedKurtosis.add(kurtosis(hammingDistances));
                calculatedSkewness.add(skewness(hammingDistances));

                histogramList.add(histogram);
            }

            String experimentType = (length == 128) ? "message" : "key";

            handleTotalHistogram(histogramList, experimentType);

            double totalMean = experimentValuesMean(calculatedMeans);
            double totalStandardDeviation = experimentValuesMean(calculatedStandardDeviation);
            double totalMedian = experimentValuesMean(calculatedMedians);
            double totalMode = experimentValuesMean(calculatedModes);
            double totalKurtosis = experimentValuesMean(calculatedKurtosis);
            double totalSkewness = experimentValuesMean(calculatedSkewness);

            System.out.println("Samples: " + sampleNumber);
            System.out.println("Mean:" + totalMean);
            System.out.println("STD: " + totalStandardDeviation);
            System.out.println("Median: " + totalMedian);
            System.out.println("Mode: " + (int) totalMode);
            System.out.println("Kurtosis: " + totalKurtosis);
            System.out.println("Skewness: " + totalSkewness);

            experimentAccuracy = calculateExperimentAccuracy(totalMean, totalStandardDeviation, calculatedMeans, calculatedStandardDeviation);
        } while (PRECISION < experimentAccuracy);

        System.out.println("Precision OK");
    }

    /**
     * Changes the messages and cipher both messsages with same key
     *
     * @return
     */
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

    /**
     * Changes key and cipher the message with both keys
     *
     * @return
     */
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

    /**
     * Cipher a message with a key using CAST256-6
     *
     * @param key
     * @param message
     * @return
     */
    private static byte[] cipherMessage(byte[] key, byte[] message) {
        byte[] cipherText = null;
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGO, bc);
            SecretKeySpec secretKey = new SecretKeySpec(key, KEY_ALGO);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            cipherText = cipher.doFinal(message);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Experiment.class.getName()).log(Level.SEVERE, null, ex);
        }
        return cipherText;
    }

    /**
     * Generates random bits for given input [0,bitLength)
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

    /**
     * Generates new sequence base on given complementing a random bit.
     *
     * @param sequence
     * @return
     */
    private static byte[] generateSimilarSequence(byte[] sequence) {
        byte[] similarSequence = new byte[sequence.length];
        System.arraycopy(sequence, 0, similarSequence, 0, sequence.length);

        int randomBit = generateRandomBitNumber(similarSequence.length * 8);

        boolean bitValue = bitValue(similarSequence, randomBit);

        return complementBit(similarSequence, randomBit, bitValue);
    }

    /**
     * Checks bit value True if bit = 1, false if = 0
     *
     * @param sequence
     * @param bit
     * @return
     */
    public static boolean bitValue(byte[] sequence, int bit) {
        int selectedByte = bit / 8;
        // Position of this bit in a byte
        int bitPosition = bit % 8;

        return ((sequence[selectedByte] >> bitPosition) & 0x01) == 1;
    }

    /**
     * Complements the given bit on the sequence
     *
     * @param sequence
     * @param bit
     * @param bitValue
     * @return
     */
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

    /**
     * Calculates hamming distance between 2 bit sequences
     *
     * @param sequence1
     * @param sequence2
     * @return
     */
    private static int hammingDistance(byte[] sequence1, byte[] sequence2) {
        int hammingDistance = 0;

        for (int i = 0; i < sequence1.length * 8; i++) {
            if (bitValue(sequence1, i) != bitValue(sequence2, i)) {
                hammingDistance++;
            }
        }
        return hammingDistance;
    }

    /**
     * Calculates mean
     *
     * @param histogram
     * @return
     */
    private static double mean(int[] histogram) {
        double[] histogramAux = new double[histogram.length];
        for (int i = 0; i < histogram.length; i++) {
            histogramAux[i] = histogram[i];
        }
        return new Mean().evaluate(histogramAux);
    }

    /**
     * Calculates Standar deviation
     *
     * @param histogram
     * @param mean
     * @return
     */
    private static double standardDeviation(int[] histogram, double mean) {
        double[] histogramAux = new double[histogram.length];
        for (int i = 0; i < histogram.length; i++) {
            histogramAux[i] = histogram[i];
        }
        return new StandardDeviation().evaluate(histogramAux);
    }

    /**
     * Calculates median
     *
     * @param histogram
     * @return
     */
    public static double median(int[] histogram) {
        int[] sortedHistogram = new int[histogram.length];

        System.arraycopy(histogram, 0, sortedHistogram, 0, histogram.length);

        Arrays.sort(sortedHistogram);

        int middle = sortedHistogram.length / 2;

        if (sortedHistogram.length % 2 == 1) {
            return sortedHistogram[middle];
        } else {
            return (sortedHistogram[middle - 1] + sortedHistogram[middle]) / 2.0;
        }
    }

    /**
     * Calculates mode
     *
     * @param histogram
     * @return
     */
    public static List<Integer> mode(int[] histogram) {
        List<Integer> modes = new ArrayList<>();
        Map<Integer, Integer> countMap = new HashMap<>();

        int max = -1;
        for (int number : histogram) {
            if (number != 0) {
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
        }
        for (Map.Entry<Integer, Integer> tuple : countMap.entrySet()) {
            if (tuple.getValue() == max) {
                modes.add(tuple.getKey());
            }
        }

        return modes;
    }

    /**
     * Calculates kurtosis
     *
     * @param histogram
     * @return
     */
    public static double kurtosis(int[] histogram) {
        double[] histogramAux = new double[histogram.length];
        for (int i = 0; i < histogram.length; i++) {
            histogramAux[i] = histogram[i];
        }

        return new Kurtosis().evaluate(histogramAux);
    }

    /**
     * Calculates skewness
     *
     * @param histogram
     * @return
     */
    public static double skewness(int[] histogram) {
        double[] histogramAux = new double[histogram.length];
        for (int i = 0; i < histogram.length; i++) {
            histogramAux[i] = histogram[i];
        }
        return new Skewness().evaluate(histogramAux);
    }

    /**
     * Calculates mean of total values
     *
     * @param values
     * @return
     */
    private static double experimentValuesMean(List<Double> values) {
        double[] histogramAux = new double[values.size()];
        for (int i = 0; i < histogramAux.length; i++) {
            histogramAux[i] = values.get(i);
        }
        return new Mean().evaluate(histogramAux);
    }

    /**
     * Calculates experiment accuracy
     *
     * @param totalMean
     * @param totalStandardDeviation
     * @param calculatedMeans
     * @param calculatedStandardDeviation
     * @return
     */
    private static double calculateExperimentAccuracy(double totalMean, double totalStandardDeviation, List<Double> calculatedMeans, List<Double> calculatedStandardDeviation) {
        double r = 0.0;
        double d = 0.0;

        for (double mean : calculatedMeans) {
            r += mean;
        }
        r -= totalMean;
        r /= totalMean;

        for (double standardDeviation : calculatedStandardDeviation) {
            d += standardDeviation;
        }
        d -= totalStandardDeviation;
        d /= totalStandardDeviation;

        return Math.max(r, d);
    }

    /**
     * Creates total histogram and writes to excel
     *
     * @param histogramList
     */
    private static void handleTotalHistogram(List<int[]> histogramList, String expType) {
        int[] totalHistogram = new int[128];
        for (int[] hist : histogramList) {
            for (int i = 0; i < totalHistogram.length; i++) {
                totalHistogram[i] += hist[i];
            }
        }

        writeToExcel(totalHistogram, "Sample" + sampleNumber + expType);
    }

    /**
     * Writes the given sequence to excel document
     *
     * @param data
     * @param excelName
     */
    private static void writeToExcel(int[] data, String excelName) {
        FileOutputStream fileOut = null;
        try {
            Workbook wb = new HSSFWorkbook();
            CreationHelper createHelper = wb.getCreationHelper();
            Sheet sheet = wb.createSheet("Histogram sheet");

            for (int i = 0; i < data.length; i++) {
                Row row = sheet.createRow((short) i);
                Cell cell = row.createCell(0);
                cell.setCellValue(data[i]);
            }
            // Write the output to a file
            fileOut = new FileOutputStream(excelName + ".xls");
            wb.write(fileOut);
            fileOut.close();
        } catch (IOException ex) {
            Logger.getLogger(Experiment.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                if (fileOut != null) {
                    fileOut.close();
                }
            } catch (IOException ex) {
                Logger.getLogger(Experiment.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    /**
     * Print bits in standar output
     *
     * @param sequence
     */
    private static void printBits(byte[] sequence) {
        String s1 = "";
        for (byte b : sequence) {
            s1 += String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0');
        }
        System.out.println(s1);
    }

    /**
     * Parse hexadecimal string to byte array
     *
     * @param string
     * @return
     */
    private static byte[] hexToByteArray(String string) {
        return Hex.decode(string);
    }

    /**
     * Parse byte array to hexadecimal string
     *
     * @param input
     * @return
     */
    private static String byteArrayToHexString(byte[] input) {
        return Hex.toHexString(input);
    }

    /**
     * Executes test random number
     */
    private static void testTotalResultsRandomNumber() {
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

    /**
     * Test random number generation
     *
     * @return
     */
    private static int[] testGenerateRandomNumber() {
        int[] results = new int[128];
        for (int i = 0; i < 100; i++) {
            results[generateRandomBitNumber(128)]++;
        }
        return results;
    }

    /**
     * Test random sequence generation
     */
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

    /**
     * Test similar sequence
     */
    private static void testGenerateSimilarSequence() {
        byte[] sequence = generateRandomBitSequence(8);
        printBits(sequence);
        byte[] sequence2 = generateSimilarSequence(sequence);
        printBits(sequence2);
        System.out.println(Arrays.equals(sequence, sequence2));
    }

    /**
     * Test hamming distance basic
     */
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

    /**
     * Test hamming distance hard
     */
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

    /**
     * Test mean and STD
     */
    private static void testMeanAndSTD() {
        int[] test = {2, 6, 4, 10, 0,};
        double mean = mean(test);
        double std = standardDeviation(test, mean);
        System.out.println("Mean: " + mean + " STD: " + std);
    }

    /**
     * Test median
     */
    private static void testMedian() {
        int[] test = {3, 13, 7, 5, 21, 23, 39, 23, 40, 23, 14, 12, 56, 23, 29};
        double median = median(test);
        System.out.println("Median: " + median);

        int[] test2 = {3, 13, 7, 5, 21, 23, 23, 40, 23, 14, 12, 56, 23, 29};
        double median2 = median(test2);
        System.out.println("Median2: " + median2);
    }

    /**
     * Test mode
     */
    private static void testMode() {
        int[] test = {3, 7, 5, 13, 20, 23, 39, 23, 40, 23, 14, 12, 56, 23, 29};
        System.out.println(mode(test));
    }

    /**
     * Test cast6 128 bit key
     */
    private static void test1CAST6() {
        System.out.println("Key size 128 bit");
        byte[] key = hexToByteArray("2342bb9efa38542c0af75647f29f615d");
        byte[] message = hexToByteArray("00000000000000000000000000000000");
        byte[] expectedMessage = hexToByteArray("c842a08972b43d20836c91d1b7530f6b");

        System.out.println(key.length);
        System.out.println(message.length);
        System.out.println(expectedMessage.length);

        byte[] cipherText = cipherMessage(key, message);

        System.out.println(cipherText.length);

        System.out.println(Arrays.equals(expectedMessage, cipherText));

        System.out.println(byteArrayToHexString(expectedMessage));
        System.out.println(byteArrayToHexString(cipherText));
    }

    /**
     * Test cast6 192 bit key
     */
    private static void test2CAST6() {
        System.out.println("Key size 192 bit");
        byte[] key = hexToByteArray("2342bb9efa38542cbed0ac83940ac298bac77a7717942863");
        byte[] message = hexToByteArray("00000000000000000000000000000000");
        byte[] expectedMessage = hexToByteArray("1b386c0210dcadcbdd0e41aa08a7a7e8");

        System.out.println(key.length);
        System.out.println(message.length);
        System.out.println(expectedMessage.length);

        byte[] cipherText = cipherMessage(key, message);

        System.out.println(cipherText.length);

        System.out.println(Arrays.equals(expectedMessage, cipherText));

        System.out.println(byteArrayToHexString(expectedMessage));
        System.out.println(byteArrayToHexString(cipherText));
    }

    /**
     * Test cast6 256 bit key
     */
    private static void test3CAST6() {
        System.out.println("Key size 256 bit");
        byte[] key = hexToByteArray("2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604");
        byte[] message = hexToByteArray("00000000000000000000000000000000");
        byte[] expectedMessage = hexToByteArray("4f6a2038286897b9c9870136553317fa");

        System.out.println(key.length);
        System.out.println(message.length);
        System.out.println(expectedMessage.length);

        byte[] cipherText = cipherMessage(key, message);

        System.out.println(cipherText.length);

        System.out.println(Arrays.equals(expectedMessage, cipherText));

        System.out.println(byteArrayToHexString(expectedMessage));
        System.out.println(byteArrayToHexString(cipherText));
    }
}
