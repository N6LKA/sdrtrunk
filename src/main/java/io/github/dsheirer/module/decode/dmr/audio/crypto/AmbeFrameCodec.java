/*
 * *****************************************************************************
 * DMR encryption support - fork-specific addition, not part of upstream.
 * ****************************************************************************
 */
package io.github.dsheirer.module.decode.dmr.audio.crypto;

import io.github.dsheirer.module.decode.dmr.audio.crypto.jmbe.BinaryFrame;
import io.github.dsheirer.module.decode.dmr.audio.crypto.jmbe.Golay23;
import io.github.dsheirer.module.decode.dmr.audio.crypto.jmbe.Golay24;

import java.nio.ByteOrder;

/**
 * Decodes a raw 9-byte DMR AMBE frame down to its 49-bit channel-coding payload,
 * and encodes that payload back into a synthetic 9-byte frame - the exact inverse
 * of jmbe.codec.ambe.AMBEFrame's private decode(), needed because that decode/encode
 * pair isn't exposed anywhere in JMBE's public API.
 *
 * decodeTo49Bits()/encodeFrom49Bits() (used for RC4 decrypt - see decodeToRawVectorBits()'s
 * javadoc for why) pack the 49 bits in raw C0/C1/C2/C3 channel-coding vector order, which is
 * the order live cross-testing against DSD-FME (github.com/lwvmobile/dsd-fme, an independent
 * decoder/encryption implementation) on real encrypted DMR traffic proved the actual
 * over-the-air encryption uses.
 *
 * decodeToB()/encode()/packTo49Bits()/unpackFrom49Bits() pack the same 49 bits in JMBE's own
 * b0..b8 voice-model parameter grouping instead - a reorganization JMBE does internally for
 * vocoder-parameter convenience, verified byte-for-byte against real, unmodified
 * jmbe.codec.ambe.AMBEFrame (20,000+ frame round-trip, see verification/ at the repo root) but
 * NOT the bit order encryption is actually applied to. Kept for that verification value and
 * because the b0..b8 breakdown is useful for future debugging, but not used by the decrypt path.
 *
 * The index arrays below are copied verbatim from AMBEFrame.java (github.com/DSheirer/jmbe) to
 * guarantee they match the real decoder.
 */
public class AmbeFrameCodec
{
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
    private static final int[] VECTOR_C3_SEQUENTIAL = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
    private static final int[] VECTOR_U3_B0_LOW = {2, 3, 4};
    private static final int[] VECTOR_U3_B1_LOW = {0};
    private static final int[] VECTOR_U3_B2_LOW = {1};
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
    private static final int[] B_WIDTHS = {7, 5, 5, 9, 7, 5, 4, 4, 3};

    private AmbeFrameCodec()
    {
    }

    /**
     * Decodes a raw 9-byte AMBE frame into its 49-bit voice parameter payload.
     * Applies the same Golay(24,12) / Golay(23,12) FEC correction and
     * descrambling as jmbe.codec.ambe.AMBEFrame's decode(), but returns the
     * flat bit payload instead of interpreting it into tone/voice model
     * parameters - that interpretation doesn't matter for decrypt, only for
     * final vocoder synthesis, which the real AMBEFrame still does
     * downstream, unmodified, after this class's encode() re-packages the
     * decrypted result.
     */
    public static long decodeTo49Bits(byte[] frame9Bytes)
    {
        return decodeToRawVectorBits(frame9Bytes);
    }

    /** Inverse of decodeTo49Bits() - encodes a 49-bit payload back to a 9-byte frame. */
    public static byte[] encodeFrom49Bits(long value49)
    {
        return encodeFromRawVectorBits(value49);
    }

    /**
     * Decodes a raw 9-byte AMBE frame into 49 bits, in the SAME order the raw C0/C1/C2/C3
     * channel-coding vectors naturally hold them (U0[12 bits] || U1[12 bits, post-descramble]
     * || C2-functional[11 bits] || C3[14 bits, natural order]) - NOT the b0..b8 voice-model
     * parameter grouping that decodeToB()/packTo49Bits() produce.
     * <p>
     * Why this exists: decodeTo49Bits() originally used packTo49Bits(decodeToB(...)), which
     * matches real JMBE's AMBEFrame.decode() perfectly (verified against 20,000+ real frames)
     * - but that b0..b8 grouping is JMBE's OWN internal reorganization of the channel bits for
     * vocoder-parameter convenience, not the actual over-the-air bit order. Live cross-testing
     * against DSD-FME (a completely independent decoder/encryption implementation) on the same
     * real encrypted DMR traffic proved the two systems' RC4 keystreams are byte-for-byte
     * identical, but the "ciphertext" bytes differed - always as a same-bit-count permutation,
     * never as different data - which only makes sense if decryption needs to operate on the
     * bits in their raw, pre-reorganization vector order, since RC4 has no notion of voice
     * parameter semantics and must be applied in the exact order the transmitter used.
     */
    static long decodeToRawVectorBits(byte[] frame9Bytes)
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

        long u0 = c0.getInt(VECTOR_U0) & 0xFFFL; //12 bits
        long u1 = ((c1.getInt(VECTOR_U1_B3_HIGH) << 4) + c1.getInt(VECTOR_U1_B4_HIGH)) & 0xFFFL; //12 bits
        long c2Functional = ((c2.getInt(VECTOR_U2_B5_HIGH) << 7) + (c2.getInt(VECTOR_U2_B6_HIGH) << 4)
            + (c2.getInt(VECTOR_U2_B7_HIGH) << 1) + c2.getInt(VECTOR_U2_B8_HIGH)) & 0x7FFL; //11 bits
        long c3All = c3.getInt(VECTOR_C3_SEQUENTIAL) & 0x3FFFL; //14 bits

        return (u0 << 37) | (u1 << 25) | (c2Functional << 14) | c3All;
    }

    /** Inverse of decodeToRawVectorBits() - encodes a raw-vector-order 49-bit payload back to a 9-byte frame. */
    static byte[] encodeFromRawVectorBits(long value49)
    {
        int u0 = (int)((value49 >>> 37) & 0xFFF);
        int u1 = (int)((value49 >>> 25) & 0xFFF);
        int c2Functional = (int)((value49 >>> 14) & 0x7FF);
        int c3All = (int)(value49 & 0x3FFF);

        BinaryFrame c0Local = new BinaryFrame(24);
        setInt(c0Local, VECTOR_U0, u0);
        golayEncode24(c0Local);

        BinaryFrame c1Data = new BinaryFrame(23);
        c1Data.load(0, 12, u1);
        golayEncode23(c1Data);
        BinaryFrame modulationVector = getModulationVector(c0Local.getInt(VECTOR_U0));
        c1Data.xor(modulationVector);

        BinaryFrame c2Local = new BinaryFrame(11);
        c2Local.load(0, 11, c2Functional);

        BinaryFrame c3Local = new BinaryFrame(14);
        c3Local.load(0, 14, c3All);

        BinaryFrame frame = new BinaryFrame(72);
        copyBitsSequential(frame, VECTOR_C0, c0Local);
        copyBitsSequential(frame, VECTOR_C1, c1Data);
        copyBitsSequential(frame, VECTOR_C2, c2Local);
        copyBitsSequential(frame, VECTOR_C3, c3Local);

        return toBytes(frame, 9);
    }

    static int[] decodeToB(byte[] frame9Bytes)
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

    static byte[] encode(int[] b)
    {
        int u0 = ((b[0] >> 3) << 8) | ((b[1] >> 1) << 4) | (b[2] >> 1);
        int u1 = ((b[3] >> 1) << 4) | (b[4] >> 3);
        int c2 = ((b[5] >> 1) << 7) | ((b[6] >> 1) << 4) | ((b[7] >> 1) << 1) | (b[8] >> 2);

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

        BinaryFrame c0Local = new BinaryFrame(24);
        setInt(c0Local, VECTOR_U0, u0);
        golayEncode24(c0Local);

        BinaryFrame c1Data = new BinaryFrame(23);
        c1Data.load(0, 12, u1);
        golayEncode23(c1Data);
        BinaryFrame modulationVector = getModulationVector(c0Local.getInt(VECTOR_U0));
        c1Data.xor(modulationVector);

        BinaryFrame c2Local = new BinaryFrame(11);
        c2Local.load(0, 11, c2);

        BinaryFrame frame = new BinaryFrame(72);
        copyBitsSequential(frame, VECTOR_C0, c0Local);
        copyBitsSequential(frame, VECTOR_C1, c1Data);
        copyBitsSequential(frame, VECTOR_C2, c2Local);
        copyBitsSequential(frame, VECTOR_C3, c3Local);

        return toBytes(frame, 9);
    }

    private static void golayEncode24(BinaryFrame c0)
    {
        int checksum = 0;
        for(int i = 0; i < 12; i++)
        {
            if(c0.get(i))
            {
                checksum ^= GOLAY_CHECKSUMS[i];
            }
        }
        c0.load(12, 11, checksum);
        if(c0.cardinality() % 2 == 1)
        {
            c0.set(23);
        }
    }

    private static void golayEncode23(BinaryFrame c1)
    {
        int checksum = 0;
        for(int i = 0; i < 12; i++)
        {
            if(c1.get(i))
            {
                checksum ^= GOLAY_CHECKSUMS[i];
            }
        }
        c1.load(12, 11, checksum);
    }

    static long packTo49Bits(int[] b)
    {
        long value = 0;
        for(int i = 0; i < 9; i++)
        {
            value = (value << B_WIDTHS[i]) | (b[i] & ((1 << B_WIDTHS[i]) - 1));
        }
        return value;
    }

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

    private static BinaryFrame extractVector(BinaryFrame frame, int[] indices)
    {
        BinaryFrame vector = new BinaryFrame(indices.length);
        for(int i = 0; i < indices.length; i++)
        {
            vector.set(i, frame.get(indices[i]));
        }
        return vector;
    }

    private static void setInt(BinaryFrame frame, int[] indices, int value)
    {
        int bit = indices.length - 1;
        for(int index : indices)
        {
            frame.set(index, ((value >> bit) & 1) == 1);
            bit--;
        }
    }

    private static void copyBitsSequential(BinaryFrame dest, int[] destIndices, BinaryFrame source)
    {
        for(int i = 0; i < destIndices.length; i++)
        {
            dest.set(destIndices[i], source.get(i));
        }
    }

    /**
     * Reproduces AMBEFrame's private getModulationVector(seed) - the PRBS
     * sequence used to descramble/re-scramble the C1 vector.
     */
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
     * Correct inverse of BinaryFrame.setByte() / fromBytes(..., LITTLE_ENDIAN):
     * local bit 0 = byte MSB, local bit 7 = byte LSB. Deliberately NOT using
     * BinaryFrame's own getByte()/getBytes() - those have a bit-shift bug
     * (confirmed by testing) and are never actually exercised by AMBEFrame's
     * own decode path, so the bug was never caught upstream.
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
}
