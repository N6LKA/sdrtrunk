package test;

import jmbe.codec.FrameType;
import jmbe.codec.ambe.AMBEFrame;
import jmbe.codec.ambe.AMBEModelParameters;

import java.util.Arrays;
import java.util.Random;

/**
 * Verifies MY OWN decode() (not borrowed from AMBEFrame) produces the exact
 * same b0..b8 as the real AMBEFrame, across random frames including ones
 * with real bit errors (to confirm the Golay correction path behaves
 * identically, not just the error-free path).
 */
public class AmbeDecodeVerify
{
    public static void main(String[] args)
    {
        Random random = new Random(42);
        int trials = 20000;
        int voiceFramesTested = 0;
        int failures = 0;
        AMBEModelParameters previous = new AMBEModelParameters();

        for(int t = 0; t < trials; t++)
        {
            byte[] raw = new byte[9];
            random.nextBytes(raw);

            AMBEFrame reference = new AMBEFrame(raw);
            if(reference.getFrameType() != FrameType.VOICE)
            {
                continue;
            }

            int[] referenceB = reference.getVoiceParameters(previous).mB;
            int[] myB = AmbeFrameCodec.decode(raw);
            voiceFramesTested++;

            if(!Arrays.equals(referenceB, myB))
            {
                failures++;
                if(failures <= 5)
                {
                    System.out.println("MISMATCH: reference=" + Arrays.toString(referenceB)
                        + " mine=" + Arrays.toString(myB));
                }
            }
        }

        System.out.println("AmbeDecodeVerify: " + trials + " random frames, " + voiceFramesTested
            + " were VOICE type, " + failures + " failures");
        if(failures > 0)
        {
            System.exit(1);
        }
    }
}
