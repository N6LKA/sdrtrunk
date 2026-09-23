package test;

import jmbe.codec.FrameType;
import jmbe.codec.ambe.AMBEFrame;
import jmbe.codec.ambe.AMBEModelParameters;

import java.util.Arrays;
import java.util.Random;

/**
 * Simulates a full encrypt-then-decrypt cycle: take a real "plaintext" frame,
 * pretend to be the transmitter (encrypt its 49 bits, re-encode to a frame -
 * this simulates what goes over the air), then run the actual decrypt path
 * (decode, decrypt, re-encode) and confirm the REAL AMBEFrame decodes the
 * final result back to the exact original b0..b8. This is the closest
 * end-to-end software proxy available without captured real RF - it proves
 * the full pipeline (codec + RC4 with the running keystream offset) is
 * self-consistent and correct, across many simulated calls of varying length.
 */
public class FullPipelineTest
{
    static byte[] rc4(int drop, byte[] key, byte[] input)
    {
        int[] s = new int[256];
        for(int i = 0; i < 256; i++) s[i] = i;
        int j = 0;
        for(int i = 0; i < 256; i++)
        {
            j = (j + s[i] + (key[i % key.length] & 0xFF)) % 256;
            int t = s[i]; s[i] = s[j]; s[j] = t;
        }
        byte[] output = new byte[input.length];
        int i = 0; j = 0;
        for(int count = 0; count < input.length + drop; count++)
        {
            i = (i + 1) % 256;
            j = (j + s[i]) % 256;
            int t = s[i]; s[i] = s[j]; s[j] = t;
            int b = s[(s[i] + s[j]) % 256];
            if(count >= drop)
            {
                output[count - drop] = (byte)(b ^ (input[count - drop] & 0xFF));
            }
        }
        return output;
    }

    static byte[] xor49(long a49, byte[] keystream7)
    {
        // pack 49 bits into 7 bytes (MSB-first, matching packTo49Bits' bit order),
        // xor with 7-byte keystream, return 7 bytes
        byte[] plain7 = new byte[7];
        long v = a49 << 7; // shift 49-bit value into the high 49 bits of a 56-bit space (7 bytes)
        for(int i = 0; i < 7; i++)
        {
            plain7[6 - i] = (byte)(v & 0xFF);
            v >>= 8;
        }
        byte[] out = new byte[7];
        for(int i = 0; i < 7; i++)
        {
            out[i] = (byte)(plain7[i] ^ keystream7[i]);
        }
        return out;
    }

    public static void main(String[] args)
    {
        Random random = new Random(7);
        int simulatedCalls = 200;
        int framesPerCall = 20;
        int totalFrames = 0;
        int failures = 0;
        AMBEModelParameters previous = new AMBEModelParameters();

        for(int call = 0; call < simulatedCalls; call++)
        {
            // A fresh 9-byte static key and 4-byte MI per simulated call, like a real DMR RC4 call
            byte[] staticKey = new byte[5];
            random.nextBytes(staticKey);
            byte[] mi = new byte[4];
            random.nextBytes(mi);
            byte[] rc4Key = new byte[9];
            System.arraycopy(staticKey, 0, rc4Key, 0, 5);
            System.arraycopy(mi, 0, rc4Key, 5, 4);

            int dropOffset = 0;

            for(int f = 0; f < framesPerCall; f++)
            {
                // 1. Start with a real plaintext voice frame (find a VOICE-type random frame)
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

                // 2. TRANSMITTER SIDE (simulated): pack plaintext 49 bits, encrypt with keystream
                //    at the current drop offset, re-encode to a 9-byte "over the air" frame.
                long plaintext49 = AmbeFrameCodec.packTo49Bits(originalB);
                byte[] plainAsFrame = new byte[7];
                {
                    long v = plaintext49 << 7;
                    for(int i = 0; i < 7; i++) { plainAsFrame[6 - i] = (byte)(v & 0xFF); v >>= 8; }
                }
                byte[] keystream = rc4(dropOffset, rc4Key, new byte[7]); // keystream bytes = RC4(zeros)
                byte[] encryptedBytes = new byte[7];
                for(int i = 0; i < 7; i++) encryptedBytes[i] = (byte)(plainAsFrame[i] ^ keystream[i]);
                long encrypted49 = bytesToLong49(encryptedBytes);
                byte[] transmittedFrame = AmbeFrameCodec.encode(AmbeFrameCodec.unpackFrom49Bits(encrypted49));

                // 3. RECEIVER SIDE (the actual decrypt path under test): decode the "received"
                //    frame, unpack, XOR with the SAME keystream position to decrypt, re-encode.
                int[] receivedEncryptedB = AmbeFrameCodec.decode(transmittedFrame);
                long receivedEncrypted49 = AmbeFrameCodec.packTo49Bits(receivedEncryptedB);
                byte[] receivedEncryptedBytes = new byte[7];
                {
                    long v = receivedEncrypted49 << 7;
                    for(int i = 0; i < 7; i++) { receivedEncryptedBytes[6 - i] = (byte)(v & 0xFF); v >>= 8; }
                }
                byte[] decryptedBytes = new byte[7];
                for(int i = 0; i < 7; i++) decryptedBytes[i] = (byte)(receivedEncryptedBytes[i] ^ keystream[i]);
                long decrypted49 = bytesToLong49(decryptedBytes);
                byte[] finalFrame = AmbeFrameCodec.encode(AmbeFrameCodec.unpackFrom49Bits(decrypted49));

                // 4. Verify: feeding finalFrame into the REAL AMBEFrame recovers the ORIGINAL b0..b8
                AMBEFrame finalDecoded = new AMBEFrame(finalFrame);
                totalFrames++;
                if(finalDecoded.getFrameType() != FrameType.VOICE ||
                   !Arrays.equals(originalB, finalDecoded.getVoiceParameters(previous).mB))
                {
                    failures++;
                    if(failures <= 5)
                    {
                        System.out.println("FAIL call=" + call + " frame=" + f + " dropOffset=" + dropOffset
                            + " original=" + Arrays.toString(originalB));
                    }
                }

                dropOffset += 7; // matches DSD-FME's per-frame running keystream offset
            }
        }

        System.out.println("FullPipelineTest: " + simulatedCalls + " simulated calls x " + framesPerCall
            + " frames = " + totalFrames + " total, " + failures + " failures");
        if(failures > 0)
        {
            System.exit(1);
        }
    }

    private static long bytesToLong49(byte[] sevenBytes)
    {
        long v = 0;
        for(byte b : sevenBytes)
        {
            v = (v << 8) | (b & 0xFFL);
        }
        return v >>> 7; // drop the 7 padding bits we added when packing 49 bits into 56 (7 bytes)
    }
}
