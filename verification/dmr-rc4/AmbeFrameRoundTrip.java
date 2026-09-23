package test;

import jmbe.codec.FrameType;
import jmbe.codec.ambe.AMBEFrame;
import jmbe.codec.ambe.AMBEModelParameters;

import java.util.Random;

/**
 * The critical test: for random raw 9-byte AMBE frames, decode with the REAL
 * (unmodified) AMBEFrame to get ground-truth b0..b8, pack those into 49 bits
 * with AmbeFrameCodec, unpack back to b0..b8, re-encode to a synthetic 9-byte
 * frame with AmbeFrameCodec.encode(), then feed THAT into the REAL AMBEFrame
 * again and confirm the decoded b0..b8 match the original ground truth.
 *
 * This proves pack/unpack/encode round-trips correctly against JMBE's actual
 * behavior - not just against my own reasoning about it. Tone frames are
 * skipped since this only concerns the VOICE frame parameter path (which is
 * what carries the encrypted data).
 */
public class AmbeFrameRoundTrip
{
    public static void main(String[] args)
    {
        Random random = new Random(999);
        int trials = 20000;
        int voiceFramesTested = 0;
        int failures = 0;
        AMBEModelParameters previous = new AMBEModelParameters();

        for(int t = 0; t < trials; t++)
        {
            byte[] raw = new byte[9];
            random.nextBytes(raw);

            AMBEFrame original = new AMBEFrame(raw);
            if(original.getFrameType() != FrameType.VOICE)
            {
                continue; // skip TONE/other frame types - not relevant to voice decrypt path
            }

            int[] groundTruthB = original.getVoiceParameters(previous).mB.clone();
            voiceFramesTested++;

            long packed = AmbeFrameCodec.packTo49Bits(groundTruthB);
            int[] unpacked = AmbeFrameCodec.unpackFrom49Bits(packed);

            boolean packUnpackOk = java.util.Arrays.equals(groundTruthB, unpacked);
            if(!packUnpackOk)
            {
                failures++;
                if(failures <= 5)
                {
                    System.out.println("PACK/UNPACK MISMATCH: " + java.util.Arrays.toString(groundTruthB)
                        + " vs " + java.util.Arrays.toString(unpacked));
                }
                continue;
            }

            byte[] reEncoded = AmbeFrameCodec.encode(unpacked);
            AMBEFrame reDecoded = new AMBEFrame(reEncoded);

            if(reDecoded.getFrameType() != FrameType.VOICE)
            {
                failures++;
                if(failures <= 5)
                {
                    System.out.println("RE-ENCODE CHANGED FRAME TYPE: original=VOICE re-decoded="
                        + reDecoded.getFrameType() + " b=" + java.util.Arrays.toString(groundTruthB));
                }
                continue;
            }

            int[] roundTrippedB = reDecoded.getVoiceParameters(previous).mB;
            boolean fullRoundTripOk = java.util.Arrays.equals(groundTruthB, roundTrippedB);

            if(!fullRoundTripOk)
            {
                failures++;
                if(failures <= 5)
                {
                    System.out.println("FULL ROUND TRIP MISMATCH: original=" + java.util.Arrays.toString(groundTruthB)
                        + " afterEncodeDecode=" + java.util.Arrays.toString(roundTrippedB));
                }
            }
        }

        System.out.println("AmbeFrameRoundTrip: " + trials + " random frames, " + voiceFramesTested
            + " were VOICE type, " + failures + " failures");
        if(failures > 0)
        {
            System.exit(1);
        }
    }
}
