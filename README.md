# N6LKA fork of sdrtrunk

This is a permanent fork of [DSheirer/sdrtrunk](https://github.com/DSheirer/sdrtrunk) that adds the
ability to manually enter known encryption keys (work-authorized keys, or personal test keys) so
SDRTrunk can automatically decrypt and play audio for encrypted P25/DMR trunked radio traffic. The
upstream project has declined to add this feature, so it lives here instead. See `keystore/` for
the key management app, and `verification/dmr-rc4/` for the DMR decrypt correctness test suite.

There are no pre-built releases for this fork - build it from source (see below). Everything else
in this README describes the underlying, unmodified sdrtrunk application.

## Building from source

Requires a **Full** JDK 21+ (BellSoft Liberica Full, or any JDK distribution that bundles the
JavaFX jmods) - a standard JDK will fail to build because it's missing `javafx.*` modules needed
for the `jlink` runtime packaging step. Gradle's own toolchain auto-provisioning will pull a
standard (non-Full) JDK by default, so point it at a Full JDK explicitly:

```
git clone https://github.com/N6LKA/sdrtrunk.git
cd sdrtrunk
git checkout develop
```

In `~/.gradle/gradle.properties`, register the Full JDK's install path so the Gradle toolchain
picks it up instead of auto-provisioning a standard one:

```
org.gradle.java.installations.paths=/path/to/your/full-jdk
org.gradle.java.installations.auto-download=false
```

Then build and run, with `JAVA_HOME` pointed at that same Full JDK (needed separately for the
`jlink`/`runtimeZipCurrent` packaging step, which uses whichever JVM runs the Gradle daemon itself,
not just the toolchain setting):

```
JAVA_HOME=/path/to/your/full-jdk ./gradlew runtimeZipCurrent
```

The resulting runtime image is under `build/image/`.

# MacOS Tahoe 26.1 Users - Attention:
Changes to USB support in Tahoe version 26.x cause sdrtrunk to fail to launch.  Do the following to install the latest libusb and create a symbolic link.  There may still be issue(s) with MacOS accessing your USB SDR tuners.

```
brew install libusb --HEAD
cd /opt
sudo mkdir local
cd local
sudo mkdir lib
```
Next, find where brew installed the libusb library, for example: ```/opt/homebrew/Cellar/libusb/HEAD-9ceaa52/lib/libusb-1.0.0.dylib```    Note: the folder "HEAD-9ceaa52" is the version stamp for HEAD when you installed from it.

Finally, create a symbolic link from the installed library to the place where usb4java is expecting to find libusb (/opt/local/lib/libusb-1.0.0.dylib)

```
sudo ln -s /opt/homebrew/Cellar/libusb/HEAD-9ceaa52/lib/libusb-1.0.0.dylib /opt/local/lib/libusb-1.0.0.dylib
```

# sdrtrunk
A cross-platform java application for decoding, monitoring, recording and streaming trunked mobile and related radio protocols using Software Defined Radios (SDR).

* [Help/Wiki Home Page](https://github.com/DSheirer/sdrtrunk/wiki) (upstream project's docs - still applies to this fork)
* [Getting Started](https://github.com/DSheirer/sdrtrunk/wiki/Getting-Started)
* [User's Manual](https://github.com/DSheirer/sdrtrunk/wiki/User-Manual)

![sdrtrunk Application](https://github.com/DSheirer/sdrtrunk/wiki/images/sdrtrunk.png)
**Figure 1:** sdrtrunk Application Screenshot

## Minimum System Requirements
* **Operating System:** Windows (~~32 or~~ 64-bit), Linux (~~32 or~~ 64-bit) or Mac (64-bit, 12.x or higher)
* **CPU:** 4-core
* **RAM:** 8GB or more (preferred).  Depending on usage, 4GB may be sufficient.
