package test;

import jmbe.binary.BinaryFrame;
import jmbe.edac.Golay23;

/**
 * Same approach as Golay24RoundTrip, but for Golay(23,12,7) - no separate
 * overall parity bit, just 12 data + 11 checksum = 23 bits.
 */
public class Golay23RoundTrip
{
    private static final int[] CHECKSUMS = new int[]
        {
            0x63A, 0x31D, 0x7B4, 0x3DA, 0x1ED, 0x6CC, 0x366, 0x1B3,
            0x6E3, 0x54B, 0x49F, 0x475
        };

    static BinaryFrame encode(int data12)
    {
        BinaryFrame frame = new BinaryFrame(23);
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

        return frame;
    }

    public static void main(String[] args)
    {
        java.util.Random random = new java.util.Random(5678);
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
                int bit = random.nextInt(23);
                if(flipped.add(bit))
                {
                    frame.flip(bit);
                }
            }

            int reportedErrors = Golay23.checkAndCorrect(frame, 0);
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

        System.out.println("Golay23RoundTrip: " + trials + " trials, " + failures + " failures");
        if(failures > 0)
        {
            System.exit(1);
        }
    }
}
