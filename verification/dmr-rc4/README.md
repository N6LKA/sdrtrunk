# DMR RC4 Decrypt Verification

Standalone verification suite for the DMR RC4 (algorithm 0x21, DMRA
Enhanced Privacy) decrypt implementation
(`src/main/java/io/github/dsheirer/module/decode/dmr/audio/crypto/`).

## Why this exists

The core problem with this work: P25/DMR encryption applies to voice codec
parameters *after* FEC error-correction decoding, not to the raw transmitted
frame bytes SDRTrunk hands to the JMBE codec - and JMBE's public interface
(and its actual codec implementation, which isn't even a compile-time
dependency of SDRTrunk) exposes no hook at that layer. Fixing this means
replicating JMBE's own FEC-decode/re-encode logic
(`AmbeFrameCodec.java`, vendored `Golay23`/`Golay24`/`BinaryFrame` from
github.com/DSheirer/jmbe) - intricate bit-level DSP code with no compiler in
some environments (like the one this was originally written in) and no
captured real encrypted DMR audio available to test against.

Rather than ship that blind, this suite verifies it against the **real,
unmodified `jmbe.codec.ambe.AMBEFrame`** class as a ground-truth oracle -
not just against reasoning about how it should work.

## What's verified

- `Golay24RoundTrip.java` / `Golay23RoundTrip.java` - the Golay(24,12,7) and
  Golay(23,12,7) FEC encode/correct round trip, against the real
  `jmbe.edac.Golay23`/`Golay24` classes, with 0-3 injected bit errors,
  5000 trials each.
- `AmbeFrameRoundTrip.java` - encodes b0..b8 to a synthetic frame, decodes
  it with the real `AMBEFrame`, confirms it recovers the original values.
  ~18,700 real VOICE-type frames out of 20,000 random trials.
- `AmbeDecodeVerify.java` - the reverse: confirms this project's own
  `decode()` produces identical b0..b8 to the real `AMBEFrame`, across the
  same ~18,700 frames (including ones needing real FEC correction).
- `Rc4Test.java` - the RC4 primitive against a standard published test
  vector (Key="Key", Plaintext="Plaintext" -> BBF316E8D940AF0AD3).
- `FullPipelineTest.java` - simulates a full encrypt-then-decrypt cycle
  (200 simulated calls x 20 frames, random keys/MIs, running keystream
  offset) using inlined logic matching the production classes.
- `ProductionPipelineTest.java` - the same simulation, but calling the
  *actual* committed production classes
  (`io.github.dsheirer.module.decode.dmr.audio.crypto.DmrRc4Decryptor`)
  directly, to close the loop between this test suite and what's really
  in the repo.

All of the above: 0 failures, last run 2026-09-23.

**What this does NOT verify:** real over-the-air encrypted audio. There was
no captured RF sample or DSD-FME-decrypted reference audio available to
compare against - this is the strongest verification achievable without
one. Treat this as "the code is internally correct and matches JMBE's real
behavior," not "confirmed against a real radio."

## Running it

Needs a JDK (any JDK 17+ is fine for this, doesn't need to match the
project's toolchain) and JMBE's codec source as an oracle:

    git clone --depth 1 https://github.com/DSheirer/jmbe.git /tmp/jmbe
    mkdir -p /tmp/dmr-verify/lib
    curl -sL -o /tmp/dmr-verify/lib/slf4j-api.jar \
      https://repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.16/slf4j-api-2.0.16.jar

    mkdir -p /tmp/dmr-verify/src
    cp -r /tmp/jmbe/codec/src/main/java/jmbe /tmp/dmr-verify/src/
    cp verification/dmr-rc4/*.java /tmp/dmr-verify/src/  # note: these declare `package test;`
    mkdir -p /tmp/dmr-verify/src/test
    mv /tmp/dmr-verify/src/*.java /tmp/dmr-verify/src/test/

    cd /tmp/dmr-verify
    javac -d out -cp lib/slf4j-api.jar -sourcepath src src/test/*.java
    for t in Golay24RoundTrip Golay23RoundTrip AmbeFrameRoundTrip AmbeDecodeVerify Rc4Test FullPipelineTest; do
      java -cp "out:lib/slf4j-api.jar" test.$t
    done

`ProductionPipelineTest` additionally needs the real project's compiled
`io.github.dsheirer.module.decode.dmr.audio.crypto.*` classes on the
classpath (build the project normally, add `build/classes/java/main` to
`-cp`, then run `java -cp out:lib/slf4j-api.jar:<build-output> test.ProductionPipelineTest`).
