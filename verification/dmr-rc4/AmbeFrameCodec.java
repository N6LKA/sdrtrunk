package test;

import jmbe.binary.BinaryFrame;
import jmbe.edac.Golay23;
import jmbe.edac.Golay24;

import java.nio.ByteOrder;

/**
 * Encodes a 49-bit AMBE voice parameter set (b0..b8) back into a 9-byte raw
 * frame that jmbe.codec.ambe.AMBEFrame will decode back to the same b0..b8
 * values - the mathematical inverse of AMBEFrame's private decode(). Index
 * arrays below are copied verbatim from AMBEFrame.java (github.com/DSheirer/jmbe)
 * to guarantee they match exactly what the real decoder expects.
 */
public class AmbeFrameCodec
{
    // --- copied verbatim from jmbe.codec.ambe.AMBEFrame ---
    private static final int[] VECTOR_C0 = {0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 1, 5,
        9, 13, 17, 21};
    private static final int[] VECTOR_C1 = {25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 2, 6, 10, 14, 18, 22, 26,
        30, 34, 38, 42};
    private static final int[] VECTOR_C2 = {46, 50, 54, 58, 62, 66, 70, 3, 7, 11, 15};
    private static final int[] VECTOR_C3 = {19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63, 67, 71};
    private static final int[] VECTOR_U0 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    private static final int[] VECTOR_U0_B0_HIGH = {0, 1, 2, 3};
    private static final int[] VECTOR_U0_B1_HIGH = {4, 5, 6, 7};
    private static final int[] VECTOR_U0_B2_HIGH = {8, 9, 10, 11};
    private static final int[] VECTOR_U1_B3_HIGH = {0, 1, 2, 3, 4, 5, 6, 7};
    private static final int[] VECTOR_U1_B4_HIGH = {8, 9, 10, 11};
    private static final int[] VECTOR_U2_B5_HIGH = {0, 1, 2, 3};
    private static final int[] VECTOR_U2_B6_HIGH = {4, 5, 6};
    private static final int[] VECTOR_U2_B7_HIGH = {7, 8, 9};
    private static final int[] VECTOR_U2_B8_HIGH = {10};
    private static final int[] VECTOR_U3_B1_LOW = {0};
    private static final int[] VECTOR_U3_B2_LOW = {1};
    private static final int[] VECTOR_U3_B0_LOW = {2, 3, 4};
    private static final int[] VECTOR_U3_B3_LOW = {5};
    private static final int[] VECTOR_U3_B4_LOW = {6, 7, 8};
    private static final int[] VECTOR_U3_B5_LOW = {9};
    private static final int[] VECTOR_U3_B6_LOW = {10};
    private static final int[] VECTOR_U3_B7_LOW = {11};
    private static final int[] VECTOR_U3_B8_LOW = {12, 13};

    private static final int[] GOLAY_CHECKSUMS = new int[]
        {
            0x63A, 0x31D, 0x7B4, 0x3DA, 0x1ED, 0x6CC, 0x366, 0x1B3,
            0x6E3, 0x54B, 0x49F, 0x475
        };

    /** Bit widths of b0..b8, MSB-first within each value - sums to 49. */
    static final int[] B_WIDTHS = {7, 5, 5, 9, 7, 5, 4, 4, 3};

    /**
     * Packs b0..b8 into a single 49-bit value, MSB-first (b0's MSB is bit 48).
     * This is the flat representation that gets XORed against the RC4 keystream.
     */
    static long packTo49Bits(int[] b)
    {
        long value = 0;
        for(int i = 0; i < 9; i++)
        {
            value = (value << B_WIDTHS[i]) | (b[i] & ((1 << B_WIDTHS[i]) - 1));
        }
        return value;
    }

    /** Inverse of packTo49Bits(). */
    static int[] unpackFrom49Bits(long value)
    {
        int[] b = new int[9];
        for(int i = 8; i >= 0; i--)
        {
            b[i] = (int)(value & ((1 << B_WIDTHS[i]) - 1));
            value >>= B_WIDTHS[i];
        }
        return b;
    }

    /** Sets bits at the given local-frame indices from value, MSB-first (mirrors BinaryFrame.getInt(int[])). */
    private static void setInt(BinaryFrame frame, int[] indices, int value)
    {
        int bit = indices.length - 1;
        for(int index : indices)
        {
            frame.set(index, ((value >> bit) & 1) == 1);
            bit--;
        }
    }

    /** Reproduces AMBEFrame's private getModulationVector(seed). */
    private static BinaryFrame getModulationVector(int seed)
    {
        BinaryFrame modulationVector = new BinaryFrame(23);
        int prX = 16 * seed;
        for(int x = 0; x < 23; x++)
        {
            prX = (173 * prX + 13849) % 65536;
            if(prX >= 32768)
            {
                modulationVector.set(x);
            }
        }
        return modulationVector;
    }

    /**
     * Decodes a raw 9-byte AMBE frame into b0..b8, mirroring AMBEFrame's
     * private decode() but returning just the raw parameter values - no tone
     * detection, no error-rate/frame-repeat smoothing, none of which matters
     * for decrypt (that logic only matters for final vocoder synthesis,
     * which the unmodified real AMBEFrame still does downstream as before).
     */
    public static int[] decode(byte[] frame9Bytes)
    {
        BinaryFrame frame = BinaryFrame.fromBytes(frame9Bytes, ByteOrder.LITTLE_ENDIAN);

        BinaryFrame c0 = extractVector(frame, VECTOR_C0);
        BinaryFrame c1 = extractVector(frame, VECTOR_C1);
        BinaryFrame c2 = extractVector(frame, VECTOR_C2);
        BinaryFrame c3 = extractVector(frame, VECTOR_C3);

        Golay24.checkAndCorrect(c0, 0);
        BinaryFrame modulationVector = getModulationVector(c0.getInt(VECTOR_U0));
        c1.xor(modulationVector);
        Golay23.checkAndCorrect(c1, 0);

        int[] b = new int[9];
        b[0] = (c0.getInt(VECTOR_U0_B0_HIGH) << 3) + c3.getInt(VECTOR_U3_B0_LOW);
        b[1] = (c0.getInt(VECTOR_U0_B1_HIGH) << 1) + c3.getInt(VECTOR_U3_B1_LOW);
        b[2] = (c0.getInt(VECTOR_U0_B2_HIGH) << 1) + c3.getInt(VECTOR_U3_B2_LOW);
        b[3] = (c1.getInt(VECTOR_U1_B3_HIGH) << 1) + c3.getInt(VECTOR_U3_B3_LOW);
        b[4] = (c1.getInt(VECTOR_U1_B4_HIGH) << 3) + c3.getInt(VECTOR_U3_B4_LOW);
        b[5] = (c2.getInt(VECTOR_U2_B5_HIGH) << 1) + c3.getInt(VECTOR_U3_B5_LOW);
        b[6] = (c2.getInt(VECTOR_U2_B6_HIGH) << 1) + c3.getInt(VECTOR_U3_B6_LOW);
        b[7] = (c2.getInt(VECTOR_U2_B7_HIGH) << 1) + c3.getInt(VECTOR_U3_B7_LOW);
        b[8] = (c2.getInt(VECTOR_U2_B8_HIGH) << 2) + c3.getInt(VECTOR_U3_B8_LOW);
        return b;
    }

    private static BinaryFrame extractVector(BinaryFrame frame, int[] indices)
    {
        BinaryFrame vector = new BinaryFrame(indices.length);
        for(int i = 0; i < indices.length; i++)
        {
            vector.set(i, frame.get(indices[i]));
        }
        return vector;
    }

    /**
     * Encodes b0..b8 (as produced by AMBEFrame.getVoiceParameters().mB) into a
     * 9-byte raw AMBE frame that AMBEFrame will decode back to the same values.
     */
    public static byte[] encode(int[] b)
    {
        // Reconstruct the 3 local vectors' data bits from b0..b8, per the exact
        // HIGH/LOW split AMBEFrame.decode() uses (inverse of that combination).
        int u0 = ((b[0] >> 3) << 8) | ((b[1] >> 1) << 4) | (b[2] >> 1);          // 12-bit C0 data
        int u1 = ((b[3] >> 1) << 4) | (b[4] >> 3);                               // 12-bit C1 data (pre-descramble)
        int c2 = ((b[5] >> 1) << 7) | ((b[6] >> 1) << 4) | ((b[7] >> 1) << 1) | (b[8] >> 2); // 11-bit, no FEC
        // 14-bit C3, built at its own local bit positions (0-13) per the LOW-part index map
        BinaryFrame c3Local = new BinaryFrame(14);
        setInt(c3Local, VECTOR_U3_B0_LOW, b[0] & 0x7);
        setInt(c3Local, VECTOR_U3_B1_LOW, b[1] & 0x1);
        setInt(c3Local, VECTOR_U3_B2_LOW, b[2] & 0x1);
        setInt(c3Local, VECTOR_U3_B3_LOW, b[3] & 0x1);
        setInt(c3Local, VECTOR_U3_B4_LOW, b[4] & 0x7);
        setInt(c3Local, VECTOR_U3_B5_LOW, b[5] & 0x1);
        setInt(c3Local, VECTOR_U3_B6_LOW, b[6] & 0x1);
        setInt(c3Local, VECTOR_U3_B7_LOW, b[7] & 0x1);
        setInt(c3Local, VECTOR_U3_B8_LOW, b[8] & 0x3);

        // Golay24-encode C0 (12 data bits -> 24-bit codeword, local positions 0-23)
        BinaryFrame c0Local = new BinaryFrame(24);
        setInt(c0Local, VECTOR_U0, u0);
        int checksum0 = 0;
        for(int i = 0; i < 12; i++)
        {
            if(c0Local.get(i))
            {
                checksum0 ^= GOLAY_CHECKSUMS[i];
            }
        }
        c0Local.load(12, 11, checksum0);
        if(c0Local.cardinality() % 2 == 1)
        {
            c0Local.set(23);
        }

        // Golay23-encode C1's 12 data bits, then re-apply the same descrambling
        // XOR used on decode (self-inverse - XOR twice with the same vector is a no-op).
        BinaryFrame c1Data = new BinaryFrame(23);
        c1Data.load(0, 12, u1);
        int checksum1 = 0;
        for(int i = 0; i < 12; i++)
        {
            if(c1Data.get(i))
            {
                checksum1 ^= GOLAY_CHECKSUMS[i];
            }
        }
        c1Data.load(12, 11, checksum1);
        BinaryFrame modulationVector = getModulationVector(c0Local.getInt(VECTOR_U0));
        c1Data.xor(modulationVector);

        BinaryFrame c2Local = new BinaryFrame(11);
        c2Local.load(0, 11, c2);

        // Scatter all 4 local vectors back into the 72-bit transmitted frame layout
        BinaryFrame frame = new BinaryFrame(72);
        copyBitsSequential(frame, VECTOR_C0, c0Local);
        copyBitsSequential(frame, VECTOR_C1, c1Data);
        copyBitsSequential(frame, VECTOR_C2, c2Local);
        copyBitsSequential(frame, VECTOR_C3, c3Local);

        return toBytes(frame, 9);
    }

    /**
     * Correct inverse of BinaryFrame.setByte() / fromBytes(..., LITTLE_ENDIAN):
     * for each byte, local bit 0 = MSB, local bit 7 = LSB. NOT the same as
     * BinaryFrame's own getByte()/getBytes(), which has an off-by-one-shift
     * bug and is not actually the inverse of setByte() (confirmed by test -
     * it's simply never exercised by AMBEFrame's own decode path, so the bug
     * was never caught upstream).
     */
    private static byte[] toBytes(BinaryFrame frame, int numBytes)
    {
        byte[] result = new byte[numBytes];
        for(int byteIndex = 0; byteIndex < numBytes; byteIndex++)
        {
            int value = 0;
            for(int bit = 0; bit < 8; bit++)
            {
                value = (value << 1) | (frame.get(byteIndex * 8 + bit) ? 1 : 0);
            }
            result[byteIndex] = (byte)value;
        }
        return result;
    }

    private static void copyBitsSequential(BinaryFrame dest, int[] destIndices, BinaryFrame source)
    {
        for(int i = 0; i < destIndices.length; i++)
        {
            dest.set(destIndices[i], source.get(i));
        }
    }
}
