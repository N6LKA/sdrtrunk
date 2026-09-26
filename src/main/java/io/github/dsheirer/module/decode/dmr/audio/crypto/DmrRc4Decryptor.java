/*
 * *****************************************************************************
 * DMR encryption support - fork-specific addition, not part of upstream.
 * ****************************************************************************
 */
package io.github.dsheirer.module.decode.dmr.audio.crypto;

/**
 * DMR Association RC4 (Enhanced Privacy, algorithm ID 0x21) voice frame
 * decryption. Does NOT implement Hytera's RC4 variant (algorithm 0x02/0x26) -
 * that scheme XORs the key and MI together instead of concatenating them,
 * and is a different, incompatible key derivation.
 *
 * Ported from DSD-FME (github.com/lwvmobile/dsd-fme), src/crypt-rc4.c
 * (rc4_voice_decrypt) and src/dsd_mbe.c (the algorithm 0x21 handling) - the
 * confirmed-working reference for this exact algorithm, verified live
 * against a real key on a real system. The RC4 primitive itself is also
 * independently verified against a standard published RC4 test vector (see
 * verification/ at the repo root).
 *
 * Key material: a 9-byte RC4 key formed by concatenating the 5-byte
 * (40-bit) static key from the keystore with the 4-byte (32-bit) per-call
 * Message Indicator from the PI Header (EncryptionParameters).
 *
 * Keystream position is NOT reset per frame - it's a running offset across
 * the whole call, advanced by 7 bytes (56 bits) per voice frame processed,
 * matching DSD-FME's per-call "drop" counter. One instance per call; never
 * share an instance across multiple calls, and construct a fresh instance
 * each time a call's encryption state (key or MI) is established.
 */
public class DmrRc4Decryptor
{
    private static final int FRAME_BYTES = 7; // packed AMBE payload size for keystream purposes (49 bits -> 7 bytes)

    // DSD-FME (dmr_le.c, dmr_alg_refresh()) starts every new call's keystream at drop offset 256,
    // not 0 - the first 256 RC4 keystream bytes are statistically biased and are discarded before
    // any real data is XORed with the stream, matching this scheme's actual over-the-air convention.
    private static final int INITIAL_DROP_OFFSET = 256;

    private final byte[] mKey; // 9 bytes: 5-byte static key + 4-byte MI
    private int mDropOffset = INITIAL_DROP_OFFSET;

    /**
     * @param staticKeyBytes the 5-byte (40-bit) key from the keystore
     * @param messageIndicator the 32-bit MI from this call's PI Header (EncryptionParameters.getInitializationVector())
     */
    public DmrRc4Decryptor(byte[] staticKeyBytes, int messageIndicator)
    {
        if(staticKeyBytes.length != 5)
        {
            throw new IllegalArgumentException("DMR RC4 key must be 5 bytes (40-bit), got " + staticKeyBytes.length);
        }

        mKey = new byte[9];
        System.arraycopy(staticKeyBytes, 0, mKey, 0, 5);
        mKey[5] = (byte)((messageIndicator >>> 24) & 0xFF);
        mKey[6] = (byte)((messageIndicator >>> 16) & 0xFF);
        mKey[7] = (byte)((messageIndicator >>> 8) & 0xFF);
        mKey[8] = (byte)(messageIndicator & 0xFF);
    }

    /**
     * Decrypts one raw 9-byte AMBE voice frame and advances the keystream
     * position for the next frame in this call.
     *
     * @param encryptedFrame raw 9-byte frame as received (still FEC-encoded/encrypted)
     * @return a 9-byte frame that the existing, unmodified JMBE IAudioCodec
     *         will decode to the original plaintext audio
     */
    public byte[] decryptFrame(byte[] encryptedFrame)
    {
        long encrypted49 = AmbeFrameCodec.decodeTo49Bits(encryptedFrame);
        byte[] encryptedBytes = to7Bytes(encrypted49);

        byte[] keystream = rc4Keystream(mDropOffset, FRAME_BYTES);
        byte[] plainBytes = new byte[FRAME_BYTES];
        for(int i = 0; i < FRAME_BYTES; i++)
        {
            plainBytes[i] = (byte)(encryptedBytes[i] ^ keystream[i]);
        }

        mDropOffset += FRAME_BYTES;
        return AmbeFrameCodec.encodeFrom49Bits(from7Bytes(plainBytes));
    }

    /**
     * Advances the keystream position without decrypting - for frames that
     * should be skipped, keeping the running offset in sync with what the
     * transmitter's encoder actually advanced past.
     */
    public void skipFrame()
    {
        mDropOffset += FRAME_BYTES;
    }

    private byte[] rc4Keystream(int drop, int length)
    {
        int[] s = new int[256];
        for(int i = 0; i < 256; i++)
        {
            s[i] = i;
        }

        int j = 0;
        for(int i = 0; i < 256; i++)
        {
            j = (j + s[i] + (mKey[i % mKey.length] & 0xFF)) % 256;
            int t = s[i];
            s[i] = s[j];
            s[j] = t;
        }

        byte[] keystream = new byte[length];
        int i = 0;
        j = 0;
        for(int count = 0; count < length + drop; count++)
        {
            i = (i + 1) % 256;
            j = (j + s[i]) % 256;
            int t = s[i];
            s[i] = s[j];
            s[j] = t;
            int b = s[(s[i] + s[j]) % 256];

            if(count >= drop)
            {
                keystream[count - drop] = (byte)b;
            }
        }

        return keystream;
    }

    private static byte[] to7Bytes(long value49)
    {
        long shifted = value49 << 7; // 49 bits -> high bits of a 56-bit (7-byte) space
        byte[] bytes = new byte[7];
        for(int i = 0; i < 7; i++)
        {
            bytes[6 - i] = (byte)(shifted & 0xFF);
            shifted >>= 8;
        }
        return bytes;
    }

    private static long from7Bytes(byte[] sevenBytes)
    {
        long value = 0;
        for(byte b : sevenBytes)
        {
            value = (value << 8) | (b & 0xFFL);
        }
        return value >>> 7; // drop the 7 padding bits added by to7Bytes()
    }
}
