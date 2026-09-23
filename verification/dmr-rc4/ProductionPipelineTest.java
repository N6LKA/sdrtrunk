package test;

import io.github.dsheirer.module.decode.dmr.audio.crypto.DmrRc4Decryptor;
import io.github.dsheirer.module.decode.dmr.audio.crypto.AmbeFrameCodec;
import jmbe.codec.FrameType;
import jmbe.codec.ambe.AMBEFrame;
import jmbe.codec.ambe.AMBEModelParameters;

import java.util.Arrays;
import java.util.Random;

/**
 * Same end-to-end simulation as FullPipelineTest, but exercising the ACTUAL
 * production classes (io.github.dsheirer.module.decode.dmr.audio.crypto.*)
 * via their real public API - closes the loop between the verified test
 * harness logic and what actually got written into the fork.
 */
public class ProductionPipelineTest
{
    public static void main(String[] args)
    {
        Random random = new Random(2026);
        int simulatedCalls = 200;
        int framesPerCall = 20;
        int totalFrames = 0;
        int failures = 0;
        AMBEModelParameters previous = new AMBEModelParameters();

        for(int call = 0; call < simulatedCalls; call++)
        {
            byte[] staticKey = new byte[5];
            random.nextBytes(staticKey);
            byte[] miBytes = new byte[4];
            random.nextBytes(miBytes);
            int mi = ((miBytes[0] & 0xFF) << 24) | ((miBytes[1] & 0xFF) << 16)
                | ((miBytes[2] & 0xFF) << 8) | (miBytes[3] & 0xFF);

            // TRANSMITTER side simulated with its own decryptor instance run "backwards"
            // (RC4 is symmetric - encrypting is the same operation as decrypting).
            DmrRc4Decryptor transmitterSide = new DmrRc4Decryptor(staticKey.clone(), mi);
            DmrRc4Decryptor receiverSide = new DmrRc4Decryptor(staticKey.clone(), mi);

            for(int f = 0; f < framesPerCall; f++)
            {
                byte[] plaintextRaw;
                int[] originalB;
                while(true)
                {
                    plaintextRaw = new byte[9];
                    random.nextBytes(plaintextRaw);
                    AMBEFrame check = new AMBEFrame(plaintextRaw);
                    if(check.getFrameType() == FrameType.VOICE)
                    {
                        originalB = check.getVoiceParameters(previous).mB.clone();
                        break;
                    }
                }

                // Simulate transmission: "decrypting" a plaintext frame through the RC4
                // decryptor is equivalent to encrypting it (RC4 XOR is symmetric) - this
                // produces the "over the air" encrypted frame at the current keystream position.
                byte[] transmittedFrame = transmitterSide.decryptFrame(plaintextRaw);

                // Receiver side: the actual decrypt path under test.
                byte[] finalFrame = receiverSide.decryptFrame(transmittedFrame);

                AMBEFrame finalDecoded = new AMBEFrame(finalFrame);
                totalFrames++;
                if(finalDecoded.getFrameType() != FrameType.VOICE ||
                   !Arrays.equals(originalB, finalDecoded.getVoiceParameters(previous).mB))
                {
                    failures++;
                    if(failures <= 5)
                    {
                        System.out.println("FAIL call=" + call + " frame=" + f
                            + " original=" + Arrays.toString(originalB));
                    }
                }
            }
        }

        System.out.println("ProductionPipelineTest: " + simulatedCalls + " calls x " + framesPerCall
            + " frames = " + totalFrames + " total, " + failures + " failures");
        if(failures > 0)
        {
            System.exit(1);
        }
    }
}
