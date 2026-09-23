package test;

import jmbe.binary.BinaryFrame;
import jmbe.edac.Golay24;

/**
 * Verifies MY Golay(24,12) encoder against the REAL JMBE Golay24.checkAndCorrect
 * (unmodified, copied verbatim from github.com/DSheirer/jmbe). Encodes random
 * 12-bit data values with my encoder, injects 0-3 random bit errors, then
 * confirms the real JMBE decoder both detects <=3 errors and recovers the
 * exact original 12-bit value.
 */
public class Golay24RoundTrip
{
    private static final int[] CHECKSUMS = new int[]
        {
            0x63A, 0x31D, 0x7B4, 0x3DA, 0x1ED, 0x6CC, 0x366, 0x1B3,
            0x6E3, 0x54B, 0x49F, 0x475
        };

    /**
     * Encodes 12 data bits into a 24-bit Golay(24,12,7) BinaryFrame, matching
     * the exact bit-position convention Golay24.checkAndCorrect expects:
     * position 0 = data MSB, positions 0-11 = data, 12-22 = checksum, 23 = parity.
     */
    static BinaryFrame encode(int data12)
    {
        BinaryFrame frame = new BinaryFrame(24);
        frame.load(0, 12, data12);

        int checksum = 0;
        for(int i = 0; i < 12; i++)
        {
            if(frame.get(i))
            {
                checksum ^= CHECKSUMS[i];
            }
        }
        frame.load(12, 11, checksum);

        int parity = frame.cardinality() % 2; // parity of data+checksum bits set so far
        if(parity == 1)
        {
            frame.set(23);
        }

        return frame;
    }

    public static void main(String[] args)
    {
        java.util.Random random = new java.util.Random(1234);
        int trials = 5000;
        int failures = 0;

        for(int t = 0; t < trials; t++)
        {
            int data = random.nextInt(1 << 12);
            BinaryFrame frame = encode(data);

            int errorCount = random.nextInt(4); // 0,1,2,3 bit errors
            java.util.Set<Integer> flipped = new java.util.HashSet<>();
            while(flipped.size() < errorCount)
            {
                int bit = random.nextInt(24);
                if(flipped.add(bit))
                {
                    frame.flip(bit);
                }
            }

            int reportedErrors = Golay24.checkAndCorrect(frame, 0);
            int correctedData = frame.getInt(0, 11);

            boolean ok = (reportedErrors <= 3) && (correctedData == data);
            if(!ok)
            {
                failures++;
                if(failures <= 5)
                {
                    System.out.println("FAIL: data=" + Integer.toBinaryString(data)
                        + " injectedErrors=" + errorCount
                        + " reportedErrors=" + reportedErrors
                        + " correctedData=" + Integer.toBinaryString(correctedData));
                }
            }
        }

        System.out.println("Golay24RoundTrip: " + trials + " trials, " + failures + " failures");
        if(failures > 0)
        {
            System.exit(1);
        }
    }
}
