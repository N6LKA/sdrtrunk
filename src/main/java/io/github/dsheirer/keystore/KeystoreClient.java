/*
 * *****************************************************************************
 * Radio Keystore integration - fork-specific addition, not part of upstream.
 * See keystore/README.md for the server side of this.
 * ****************************************************************************
 */
package io.github.dsheirer.keystore;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;

/**
 * HTTP client for the Radio Keystore (keystore/ in this repo) - a local
 * Flask app + SQLite store for manually-entered P25/DMR/NXDN decryption
 * keys, since SDRTrunk itself has no way to hold key material. See
 * keystore/README.md for the server side.
 *
 * The keystore is expected to run on the same machine as SDRTrunk - that's
 * the whole point of this design, key material never leaves the box. Base
 * URL is overridable via the sdrtrunk.keystore.url system property for
 * anyone running it on a different host or port.
 *
 * A lookup happens once per call (at PI header / encryption sync time), not
 * per audio frame, so no caching is implemented here - a local HTTP round
 * trip per call is cheap enough not to bother.
 */
public class KeystoreClient
{
    private static final Logger mLog = LoggerFactory.getLogger(KeystoreClient.class);
    private static final String DEFAULT_BASE_URL = "http://127.0.0.1:5901";
    private static final Duration TIMEOUT = Duration.ofSeconds(2);

    private final String mBaseUrl;
    private final HttpClient mHttpClient;
    private final Gson mGson;

    public KeystoreClient()
    {
        this(System.getProperty("sdrtrunk.keystore.url", DEFAULT_BASE_URL));
    }

    public KeystoreClient(String baseUrl)
    {
        mBaseUrl = baseUrl;
        mHttpClient = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
        mGson = new Gson();
    }

    /**
     * Looks up a decryption key from the keystore.
     *
     * @param protocol "P25", "DMR", or "NXDN"
     * @param identifier the system identifier as configured in the keystore.
     *        For P25 this is the WACN/SYSID hex string. DMR and NXDN have no
     *        broadcast system identifier of their own, so this must be
     *        whatever label the channel's configured alias list is named to
     *        - it has to match the "Identifier" field entered for that
     *        system in the keystore web UI exactly.
     * @param algorithmId the over-the-air algorithm ID for this call
     * @param keyId the over-the-air key ID for this call
     * @return the raw key bytes if an active key is found, empty otherwise.
     *         "Not found", "keystore unreachable", and "malformed response"
     *         are all treated identically - no key available, caller falls
     *         back to not decrypting - so a down keystore fails safe rather
     *         than crashing the decoder.
     */
    public Optional<byte[]> lookupKey(String protocol, String identifier, int algorithmId, int keyId)
    {
        if(identifier == null || identifier.isBlank())
        {
            return Optional.empty();
        }

        try
        {
            String url = mBaseUrl + "/api/keys/lookup"
                + "?protocol=" + URLEncoder.encode(protocol, StandardCharsets.UTF_8)
                + "&identifier=" + URLEncoder.encode(identifier, StandardCharsets.UTF_8)
                + "&algorithm_id=" + algorithmId
                + "&key_id=" + keyId;

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(TIMEOUT)
                .GET()
                .build();

            HttpResponse<String> response = mHttpClient.send(request, HttpResponse.BodyHandlers.ofString());
            LookupResponse parsed = mGson.fromJson(response.body(), LookupResponse.class);

            if(parsed == null || !parsed.found || parsed.key_value_hex == null)
            {
                return Optional.empty();
            }

            return Optional.of(hexToBytes(parsed.key_value_hex));
        }
        catch(IOException e)
        {
            mLog.warn("Unable to reach Radio Keystore at " + mBaseUrl + " for " + protocol + "/" + identifier +
                " algorithm=" + algorithmId + " key=" + keyId + " - " + e.getMessage());
            return Optional.empty();
        }
        catch(InterruptedException e)
        {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
        catch(JsonSyntaxException | IllegalArgumentException e)
        {
            //Malformed JSON or malformed hex in the response - treat as "no key", don't crash the decoder
            mLog.warn("Malformed response from Radio Keystore for " + protocol + "/" + identifier + " - " +
                e.getMessage());
            return Optional.empty();
        }
    }

    private static byte[] hexToBytes(String hex)
    {
        if(hex.length() % 2 != 0)
        {
            throw new IllegalArgumentException("Hex key value must have an even number of characters: " + hex);
        }

        byte[] bytes = new byte[hex.length() / 2];

        for(int i = 0; i < hex.length(); i += 2)
        {
            int high = Character.digit(hex.charAt(i), 16);
            int low = Character.digit(hex.charAt(i + 1), 16);

            if(high < 0 || low < 0)
            {
                throw new IllegalArgumentException("Non-hex character in key value: " + hex);
            }

            bytes[i / 2] = (byte)((high << 4) + low);
        }

        return bytes;
    }

    /** Shape of the /api/keys/lookup JSON response - see keystore/server.py api_lookup_key(). */
    private static class LookupResponse
    {
        boolean found;
        String key_value_hex;
        int key_length_bits;
        String algorithm_name;
    }
}
