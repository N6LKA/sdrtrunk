package test;

import java.nio.charset.StandardCharsets;

/**
 * Verifies the RC4 primitive (ported from DSD-FME's rc4_voice_decrypt,
 * src/crypt-rc4.c) against a well-known published RC4 test vector, decoupled
 * from any AMBE/DMR-specific framing.
 */
public class Rc4Test
{
    static byte[] rc4(int drop, byte[] key, byte[] input)
    {
        int[] s = new int[256];
        for(int i = 0; i < 256; i++)
        {
            s[i] = i;
        }

        int j = 0;
        for(int i = 0; i < 256; i++)
        {
            j = (j + s[i] + (key[i % key.length] & 0xFF)) % 256;
            int t = s[i];
            s[i] = s[j];
            s[j] = t;
        }

        byte[] output = new byte[input.length];
        int i = 0;
        j = 0;
        for(int count = 0; count < input.length + drop; count++)
        {
            i = (i + 1) % 256;
            j = (j + s[i]) % 256;
            int t = s[i];
            s[i] = s[j];
            s[j] = t;
            int b = s[(s[i] + s[j]) % 256];

            if(count >= drop)
            {
                output[count - drop] = (byte)(b ^ (input[count - drop] & 0xFF));
            }
        }

        return output;
    }

    public static void main(String[] args)
    {
        // Well-known RC4 test vector: Key="Key", Plaintext="Plaintext" -> BBF316E8D940AF0AD3
        byte[] key = "Key".getBytes(StandardCharsets.US_ASCII);
        byte[] plaintext = "Plaintext".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = hexToBytes("BBF316E8D940AF0AD3");

        byte[] actual = rc4(0, key, plaintext);

        StringBuilder hex = new StringBuilder();
        for(byte b : actual)
        {
            hex.append(String.format("%02X", b));
        }

        boolean match = java.util.Arrays.equals(expected, actual);
        System.out.println("RC4 standard test vector: expected=BBF316E8D940AF0AD3 actual=" + hex + " match=" + match);

        // Sanity check the "drop" parameter behaves as a keystream offset:
        // encrypting then decrypting with the same drop should round-trip.
        byte[] key2 = {0x00, 0x00, 0x00, 0x07, 0x77, 0x00, 0x00, 0x00, 0x0A}; // arbitrary 9-byte DMR-style key
        byte[] frame = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        byte[] cipher = rc4(14, key2, frame); // drop=14 simulating 2 prior frames processed
        byte[] recovered = rc4(14, key2, cipher);
        boolean roundTripOk = java.util.Arrays.equals(frame, recovered);
        System.out.println("RC4 drop-offset round trip: match=" + roundTripOk);

        if(!match || !roundTripOk)
        {
            System.exit(1);
        }
    }

    private static byte[] hexToBytes(String hex)
    {
        byte[] bytes = new byte[hex.length() / 2];
        for(int i = 0; i < hex.length(); i += 2)
        {
            bytes[i / 2] = (byte)Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }
}
