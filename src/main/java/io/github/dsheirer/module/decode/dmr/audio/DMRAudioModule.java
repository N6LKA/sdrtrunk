/*
 * *****************************************************************************
 * Copyright (C) 2014-2024 Dennis Sheirer
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 * ****************************************************************************
 */
package io.github.dsheirer.module.decode.dmr.audio;

import io.github.dsheirer.alias.AliasList;
import io.github.dsheirer.audio.codec.mbe.AmbeAudioModule;
import io.github.dsheirer.audio.squelch.SquelchState;
import io.github.dsheirer.audio.squelch.SquelchStateEvent;
import io.github.dsheirer.identifier.IdentifierUpdateNotification;
import io.github.dsheirer.identifier.IdentifierUpdateProvider;
import io.github.dsheirer.identifier.Role;
import io.github.dsheirer.identifier.tone.AmbeTone;
import io.github.dsheirer.identifier.tone.Tone;
import io.github.dsheirer.identifier.tone.ToneIdentifier;
import io.github.dsheirer.identifier.tone.ToneIdentifierMessage;
import io.github.dsheirer.identifier.tone.ToneSequence;
import io.github.dsheirer.keystore.KeystoreClient;
import io.github.dsheirer.message.IMessage;
import io.github.dsheirer.message.IMessageProvider;
import io.github.dsheirer.module.decode.dmr.audio.crypto.DmrRc4Decryptor;
import io.github.dsheirer.module.decode.dmr.identifier.DMRToneIdentifier;
import io.github.dsheirer.module.decode.dmr.message.data.header.PiHeader;
import io.github.dsheirer.module.decode.dmr.message.data.header.VoiceHeader;
import io.github.dsheirer.module.decode.dmr.message.data.lc.full.AbstractVoiceChannelUser;
import io.github.dsheirer.module.decode.dmr.message.data.lc.full.EncryptionParameters;
import io.github.dsheirer.module.decode.dmr.message.data.terminator.Terminator;
import io.github.dsheirer.module.decode.dmr.message.type.EncryptionAlgorithm;
import io.github.dsheirer.module.decode.dmr.message.voice.VoiceEMBMessage;
import io.github.dsheirer.module.decode.dmr.message.voice.VoiceMessage;
import io.github.dsheirer.module.decode.dmr.message.voice.embedded.EmbeddedEncryptionParameters;
import io.github.dsheirer.preference.UserPreferences;
import io.github.dsheirer.protocol.Protocol;
import io.github.dsheirer.sample.Listener;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import jmbe.iface.IAudioWithMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * DMR Audio Module for converting transmitted AMBE audio frames to 8 kHz PCM audio
 */
public class DMRAudioModule extends AmbeAudioModule implements IdentifierUpdateProvider, IMessageProvider
{
    private final static Logger mLog = LoggerFactory.getLogger(DMRAudioModule.class);
    private SquelchStateListener mSquelchStateListener = new SquelchStateListener();
    private ToneMetadataProcessor mToneMetadataProcessor = new ToneMetadataProcessor();
    private Listener<IdentifierUpdateNotification> mIdentifierUpdateNotificationListener;
    private List<byte[]> mQueuedAmbeFrames = new ArrayList<>();
    private boolean mEncryptedCallStateEstablished = false;
    private boolean mEncryptedCall = false;
    private Listener<IMessage> mMessageListener;
    private final AliasList mChannelAliasList;
    private final KeystoreClient mKeystoreClient = new KeystoreClient();
    private DmrRc4Decryptor mRc4Decryptor;

    /**
     * Constructs an instance
     * @param userPreferences for JMBE library location
     * @param aliasList for audio
     * @param timeslot for this audio module
     */
    public DMRAudioModule(UserPreferences userPreferences, AliasList aliasList, int timeslot)
    {
        super(userPreferences, aliasList, timeslot);
        mChannelAliasList = aliasList;
    }

    @Override
    public Listener<SquelchStateEvent> getSquelchStateListener()
    {
        return mSquelchStateListener;
    }

    @Override
    public void reset()
    {
        //Explicitly clear FROM identifiers to ensure previous call TONE identifiers are cleared.
        mIdentifierCollection.remove(Role.FROM);

        mEncryptedCall = false;
        mEncryptedCallStateEstablished = false;
        mRc4Decryptor = null;
        mQueuedAmbeFrames.clear();
    }

    @Override
    public void start()
    {
    }

    /**
     * Processes DMR AMBE audio frames and signalling messages.
     */
    public void receive(IMessage message)
    {
        if(hasAudioCodec() && message.getTimeslot() == getTimeslot())
        {
            //Attempt to set the audio encryption state from certain types of messages
            if(!mEncryptedCallStateEstablished)
            {
                //DCDM doesn't provide FLCs or EMBs ... assume that the call is unencrypted.
                if(message instanceof VoiceMessage vm && vm.getSyncPattern().isDirect())
                {
                    mEncryptedCallStateEstablished = true;
                    mEncryptedCall = false;
                }
                //Both Motorola and Hytera signal their Basic Privacy (BP) scrambling in some of the Voice B-F frames
                //in the EMB field.
                else if(message instanceof VoiceEMBMessage voice)
                {
                    if(voice.hasEmbeddedParameters() &&
                       voice.getEmbeddedParameters().getShortBurst() instanceof EmbeddedEncryptionParameters)
                    {
                        mEncryptedCallStateEstablished = true;
                        mEncryptedCall = true;
                    }
                    else if(voice.getEMB().isValid())
                    {
                        mEncryptedCallStateEstablished = true;
                        mEncryptedCall = voice.getEMB().isEncrypted();
                    }
                }
                else if(message instanceof VoiceHeader vh && vh.getLCMessage() instanceof AbstractVoiceChannelUser vcu &&
                        vcu.isValid())
                {
                    mEncryptedCallStateEstablished = true;
                    mEncryptedCall = vcu.getServiceOptions().isEncrypted();
                }
                else if(message instanceof PiHeader pi && pi.getLCMessage() instanceof EncryptionParameters ep &&
                        ep.isValid())
                {
                    mEncryptedCallStateEstablished = true;
                    mEncryptedCall = true;
                    mRc4Decryptor = createDecryptorIfPossible(ep);
                }
                //Note: the DMRMessageProcessor extracts Full Link Control messages from Voice Frames B-C and sends them
                // independent of any DMR Burst messaging.  When encountered, it can be assumed that they are part of
                // an ongoing call and can be used to establish encryption state when the FLC is a voice channel user.
                else if(message instanceof AbstractVoiceChannelUser avcu && avcu.isValid())
                {
                    mEncryptedCallStateEstablished = true;
                    mEncryptedCall = avcu.getServiceOptions().isEncrypted();
                }

                //Only the PiHeader/EncryptionParameters branch above carries the algorithm, key ID, and
                //initialization vector needed to decrypt - none of the other paths that can establish
                //mEncryptedCall (short burst embedded params, service options flags) carry an IV, so a
                //decryptor can never be built from them alone. If this call's encrypted state was
                //established some other way, mRc4Decryptor stays null and frames get dropped as before.
                if(mEncryptedCall && mRc4Decryptor == null)
                {
                    mQueuedAmbeFrames.clear();
                }
            }

            //Queue or process audio frames.  Note: audio frames are held/queued until encrypted state is established
            //before any audio is generated for the audio segment.
            if(message instanceof VoiceMessage voiceMessage)
            {
                for(byte[] frame: voiceMessage.getAMBEFrames())
                {
                    processAudio(frame, message.getTimestamp());
                }
            }
            else if(message instanceof Terminator)
            {
                reset();
            }
        }
    }

    /**
     * Attempts to build an RC4 decryptor for the current call from this call's PI Header encryption
     * parameters, by looking up the static key from the Radio Keystore (keystore/ in this repo). Returns
     * null (meaning: fall back to dropping encrypted audio, same as always) if the algorithm isn't DMRA
     * RC4 (0x21 - this class doesn't implement Hytera's incompatible RC4 variant), if this channel's
     * alias list isn't named to match a keystore system identifier, or if no active key is found there.
     */
    private DmrRc4Decryptor createDecryptorIfPossible(EncryptionParameters encryptionParameters)
    {
        if(encryptionParameters.getAlgorithm() != EncryptionAlgorithm.DMRA_RC4)
        {
            return null;
        }

        //AliasList.hasName() is private, so replicate its check here (non-null, non-empty name).
        if(mChannelAliasList == null || mChannelAliasList.getName() == null || mChannelAliasList.getName().isEmpty())
        {
            return null;
        }

        try
        {
            Optional<byte[]> keyBytes = mKeystoreClient.lookupKey("DMR", mChannelAliasList.getName(),
                EncryptionAlgorithm.DMRA_RC4.getValue(), encryptionParameters.getKeyId());

            if(keyBytes.isEmpty() || keyBytes.get().length != 5)
            {
                return null;
            }

            int iv = (int)Long.parseLong(encryptionParameters.getInitializationVector(), 16);
            return new DmrRc4Decryptor(keyBytes.get(), iv);
        }
        catch(Exception e)
        {
            mLog.error("Error building DMR RC4 decryptor - encrypted audio will be dropped for this call ["
                + e.getMessage() + "]");
            return null;
        }
    }

    /**
     * Processes the audio frame.  Queues the frame until encryption state is determined.  Once determined, the audio
     * frames are dequeued and audio is generated - decrypted first, if this call is encrypted and a decryptor is
     * available for it.
     */
    private void processAudio(byte[] frame, long timestamp)
    {
        if(mEncryptedCallStateEstablished)
        {
            if(mEncryptedCall && mRc4Decryptor == null)
            {
                mQueuedAmbeFrames.clear();
            }
            else
            {
                //Process any ambe frames that were queued awaiting encryption state determination
                if(!mQueuedAmbeFrames.isEmpty())
                {
                    for(byte[] queuedFrame: mQueuedAmbeFrames)
                    {
                        produceDecryptedAudio(queuedFrame, timestamp);
                    }

                    mQueuedAmbeFrames.clear();
                }

                produceDecryptedAudio(frame, timestamp);
            }
        }
        else
        {
            mQueuedAmbeFrames.add(frame);
        }
    }

    /**
     * Decrypts the frame first, if this call is encrypted and a decryptor is available - otherwise produces
     * audio directly, same as an unencrypted call. On a decrypt failure, logs and skips producing audio for
     * just that one frame rather than risk feeding raw encrypted bytes into the vocoder.
     */
    private void produceDecryptedAudio(byte[] frame, long timestamp)
    {
        if(mEncryptedCall && mRc4Decryptor != null)
        {
            try
            {
                produceAudio(mRc4Decryptor.decryptFrame(frame), timestamp);
            }
            catch(Exception e)
            {
                mLog.error("Error decrypting DMR RC4 voice frame - skipping this frame [" + e.getMessage() + "]");
            }
        }
        else
        {
            produceAudio(frame, timestamp);
        }
    }

    private void produceAudio(byte[] frame, long timestamp)
    {
        try
        {
            IAudioWithMetadata audioWithMetadata = getAudioCodec().getAudioWithMetadata(frame);
            addAudio(audioWithMetadata.getAudio());
            processMetadata(audioWithMetadata, timestamp);
        }
        catch(Exception e)
        {
            mLog.error("Error synthesizing DMR AMBE audio - continuing [" + e.getMessage() + "]");
        }
    }

    /**
     * Processes optional metadata that can be included with decoded audio (ie dtmf, tones, knox, etc.) so that the
     * tone metadata can be converted into a FROM identifier and included with any call segment.
     */
    private void processMetadata(IAudioWithMetadata audioWithMetadata, long timestamp)
    {
        if(audioWithMetadata.hasMetadata())
        {
            //JMBE only places 1 entry in the map, but for consistency we'll process the map entry set
            for(Map.Entry<String,String> entry: audioWithMetadata.getMetadata().entrySet())
            {
                //Each metadata map entry contains a tone-type (key) and tone (value)
                ToneIdentifier metadataIdentifier = mToneMetadataProcessor.process(entry.getKey(), entry.getValue());

                if(metadataIdentifier != null)
                {
                    broadcast(metadataIdentifier, timestamp);
                }
            }
        }
        else
        {
            mToneMetadataProcessor.closeMetadata();
        }
    }

    /**
     * Broadcasts the identifier to a registered listener
     */
    private void broadcast(ToneIdentifier identifier, long timestamp)
    {
        if(mIdentifierUpdateNotificationListener != null)
        {
            mIdentifierUpdateNotificationListener.receive(new IdentifierUpdateNotification(identifier,
                IdentifierUpdateNotification.Operation.ADD, getTimeslot()));
        }

        if(mMessageListener != null)
        {
            StringBuilder sb = new StringBuilder();
            sb.append("DMR Timeslot ");
            sb.append(getTimeslot());
            sb.append("Audio Tone Sequence Decoded: ");
            sb.append(identifier.toString());

            mMessageListener.receive(new ToneIdentifierMessage(Protocol.DMR, getTimeslot(), timestamp,
                    identifier, sb.toString()));
        }
    }

    /**
     * Registers the listener to receive identifier updates
     */
    @Override
    public void setIdentifierUpdateListener(Listener<IdentifierUpdateNotification> listener)
    {
        mIdentifierUpdateNotificationListener = listener;
    }

    /**
     * Unregisters a listener from receiving identifier updates
     */
    @Override
    public void removeIdentifierUpdateListener()
    {
        mIdentifierUpdateNotificationListener = null;
    }

    /**
     * Registers the listener to receive tone identifier messages from this module.
     * @param listener to receive messages
     */
    @Override
    public void setMessageListener(Listener<IMessage> listener)
    {
        mMessageListener = listener;
    }

    /**
     * Unregisters the message listener
     */
    @Override
    public void removeMessageListener()
    {
        mMessageListener = null;
    }

    /**
     * Wrapper for squelch state to process end of call actions.  At call end the encrypted call state established
     * flag is reset so that the encrypted audio state for the next call can be properly detected and we send an
     * END audio packet so that downstream processors like the audio recorder can properly close out a call sequence.
     */
    public class SquelchStateListener implements Listener<SquelchStateEvent>
    {
        @Override
        public void receive(SquelchStateEvent event)
        {
            if(event.getTimeslot() == getTimeslot() && event.getSquelchState() == SquelchState.SQUELCH)
            {
                closeAudioSegment();
            }
        }
    }

    /**
     * Process AMBE audio frame tone metadata.  Tracks the count of sequential frames containing tone metadata to
     * provide a list of each unique tone and a time duration (milliseconds) for the tone.  Tones are concatenated into
     * a comma separated list and included as call segment metadata.
     */
    public class ToneMetadataProcessor
    {
        private List<Tone> mTones = new ArrayList<>();
        private Tone mCurrentTone;

        /**
         * Resets or clears any accumulated call tone sequences to prepare for the next call.
         */
        public void reset()
        {
            mTones.clear();
        }

        /**
         * Process the tone metadata
         * @param type of tone
         * @param value of tone
         * @return an identifier with the accumulated tone metadata set
         */
        public ToneIdentifier process(String type, String value)
        {
            if(type == null || value == null)
            {
                return null;
            }

            AmbeTone tone = AmbeTone.fromValues(type, value);

            if(tone == AmbeTone.INVALID)
            {
                return null;
            }

            if(mCurrentTone == null || mCurrentTone.getAmbeTone() != tone)
            {
                mCurrentTone = new Tone(tone);
                mTones.add(mCurrentTone);
            }

            mCurrentTone.incrementDuration();

            return DMRToneIdentifier.create(new ToneSequence(new ArrayList<>(mTones)));
        }

        /**
         * Closes current tone metadata when there is no metadata for the current audio frame.
         */
        public void closeMetadata()
        {
            mCurrentTone = null;
        }
    }
}
