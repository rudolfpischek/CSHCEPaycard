package services;

import android.content.Intent;
import android.content.SharedPreferences;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.util.Log;
import cz.csas.android.hcepaycard.app.Dashboard;
import cz.csas.android.hcepaycard.app.Util;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static cz.csas.android.hcepaycard.app.Constants.DEFAULT_SWIPE_DATA;
import static cz.csas.android.hcepaycard.app.Constants.SWIPE_DATA_PREF_KEY;


public class MyHostApduService extends HostApduService implements SharedPreferences.OnSharedPreferenceChangeListener {

    private static final String TAG = MyHostApduService.class.getSimpleName();

    private static final byte[] ISO7816_UNKNOWN_ERROR_RESPONSE = {
            (byte)0x6F, (byte)0x00
    };

    /*
     *  PPSE (Proximity Payment System Environment)
     *
     *  Prvni select v poradi, ktery jde od posu smerem k platebnimu zarizen
     */
    private static final byte[] PPSE_APDU_SELECT = {
            (byte)0x00, // CLA
            (byte)0xA4, // INS
            (byte)0x04, // P1
            (byte)0x00, // P2
            (byte)0x0E, // LC
            // 2PAY.SYS.DDF01:
            // Timto se vyzada seznam aplikaci, ktere platebni zarizeni podporuje
            // vraci seznam AIDs
            '2', 'P', 'A', 'Y', '.', 'S', 'Y', 'S', '.', 'D', 'D', 'F', '0', '1',
            (byte)0x00 // LE
    };

    private static final byte[] PPSE_APDU_SELECT_RESP = {
            (byte)0x6F,  // FCI Template
            (byte)0x23,  // length = 35
            (byte)0x84,  // DF Name
            (byte)0x0E,  // length("2PAY.SYS.DDF01")
            '2', 'P', 'A', 'Y', '.', 'S', 'Y', 'S', '.', 'D', 'D', 'F', '0', '1',
            (byte)0xA5, // FCI Proprietary Template
            (byte)0x11, // length = 17
            (byte)0xBF, // FCI Issuer Discretionary Data
            (byte)0x0C, // length = 12
            (byte)0x0E,
            (byte)0x61, // Directory Entry
            (byte)0x0C, // Entry length = 12
            (byte)0x4F, // ADF Name
            (byte)0x07, // ADF Length = 7
            // Rekneme posu, ze podporujeme VISU
            // Visa credit or debit applet: A0000000031010
            // Visa's RID (Registered application provider IDentifier) 5 bytes:
            (byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03,
            (byte)0x10, (byte)0x10,
            (byte)0x87,  // Application Priority Indicator
            (byte)0x01,  // length = 1
            (byte)0x01,
            (byte) 0x90, // SW1  (90 00 = Success)
            (byte) 0x00  // SW2
    };

    /*
     *  MSD (Magnetic Stripe Data)
     */
    private static final byte[] VISA_MSD_SELECT = {
            (byte)0x00,  // CLA
            (byte)0xa4,  // INS
            (byte)0x04,  // P1
            (byte)0x00,  // P2
            (byte)0x07,  // LC (data length = 7)
            // POS vybira AID (Visa debit or credit) tak jak jsme specifikovali v PPSE response
            (byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03, (byte)0x10, (byte)0x10,
            (byte)0x00   // LE
    };


    private static final byte[] VISA_MSD_SELECT_RESPONSE = {
            (byte) 0x6F,
            (byte) 0x1E,
            (byte) 0x84,
            (byte) 0x07,
            // A0000000031010  (Visa debit or credit AID)
            (byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03, (byte)0x10, (byte)0x10,

            (byte) 0xA5,
            (byte) 0x13,
            (byte) 0x50,  // Application Label
            (byte) 0x0B,
            'V', 'I', 'S', 'A', ' ', 'C', 'R', 'E', 'D', 'I', 'T',
            (byte) 0x9F, (byte) 0x38,  // Processing Options Data Object List (PDOL)
            (byte) 0x03,  // length
            (byte) 0x9F, (byte) 0x66, (byte) 0x02, // PDOL value (Does this request terminal type?)
            (byte) 0x90,  // SW1
            (byte) 0x00   // SW2
    };


    /*
     *  GPO (Get Processing Options) command, druhy krok challenge
     */
    private static final byte[] GPO_COMMAND = {
            (byte) 0x80,  // CLA
            (byte) 0xA8,  // INS
            (byte) 0x00,  // P1
            (byte) 0x00,  // P2
            (byte) 0x04,  // LC (length)
            // data
            (byte) 0x83,  // tag
            (byte) 0x02,  // length
            (byte) 0x80,
            (byte) 0x00,
            (byte) 0x00   // Le
    };


    /*
     *  jen checkujeme, jestli se jedna o GPO command, data v request se jinak dale mohou lisit
     */
    private boolean isGpoCommand(byte[] apdu) {
        return (apdu.length > 4 &&
                apdu[0] == GPO_COMMAND[0] &&
                apdu[1] == GPO_COMMAND[1] &&
                apdu[2] == GPO_COMMAND[2] &&
                apdu[3] == GPO_COMMAND[3]
        );
    }


    /*
     *  Staticka odpoved, pouze pro podporu VISA MSD
     */
    private static final byte[] GPO_COMMAND_RESPONSE = {
            (byte) 0x80,
            (byte) 0x06,  // length
            (byte) 0x00,
            (byte) 0x80,
            (byte) 0x08,
            (byte) 0x01,
            (byte) 0x01,
            (byte) 0x00,
            (byte) 0x90,  // SW1
            (byte) 0x00   // SW2
    };


    private static final byte[] READ_REC_COMMAND = {
            (byte) 0x00,  // CLA
            (byte) 0xB2,  // INS
            (byte) 0x01,  // P1
            (byte) 0x0C,  // P2
            (byte) 0x00   // length
    };


    private static final Pattern TRACK_2_PATTERN = Pattern.compile(".*;(\\d{12,19}=\\d{1,128})\\?.*");

    private static byte[] readRecResponse = {};

    private static void configureReadRecResponse(String swipeData) {
        Matcher matcher = TRACK_2_PATTERN.matcher(swipeData);
        if (matcher.matches()) {

            String track2EquivData = matcher.group(1);
            // prevedeni track2 do pozadovane reprezentace
            track2EquivData = track2EquivData.replace('=', 'D');
            if (track2EquivData.length() % 2 != 0) {
                // pridat 'F' aby z hex stringu bylo cely cislo
                track2EquivData += "F";
            }

            int track2EquivByteLen = track2EquivData.length()/2;

            readRecResponse = new byte[6 + track2EquivByteLen];

            ByteBuffer bb = ByteBuffer.wrap(readRecResponse);
            bb.put((byte) 0x70);                            // EMV Record Template tag
            bb.put((byte) (track2EquivByteLen + 2));        // Length with track 2 tag
            bb.put((byte) 0x57);                                // Track 2 Equivalent Data tag
            bb.put((byte)track2EquivByteLen);                   // Track 2 data length
            bb.put(Util.hexToByteArray(track2EquivData));           // Track 2 equivalent data
            bb.put((byte) 0x90);                            // SW1
            bb.put((byte) 0x00);                            // SW2
        } else {
            Log.v(TAG, "Swipedata nepouzitelna");
        }



    }

    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle bundle) {
        String inboundApduDescription;
        byte[] responseApdu;

        if (Arrays.equals(PPSE_APDU_SELECT, commandApdu)) {
            inboundApduDescription = "Krok #1 PPSE select: ";
            responseApdu = PPSE_APDU_SELECT_RESP;
        } else if (Arrays.equals(VISA_MSD_SELECT, commandApdu)) {
            inboundApduDescription =  "Krok #2 Visa-MSD select: ";
            responseApdu =  VISA_MSD_SELECT_RESPONSE;
        } else if (isGpoCommand(commandApdu)) {
            inboundApduDescription =  "Krok #3 GPO (get processing options): ";
            responseApdu =  GPO_COMMAND_RESPONSE;
        } else if (Arrays.equals(READ_REC_COMMAND, commandApdu)) {
            inboundApduDescription = "Krok #4 READ REC: ";
            responseApdu = readRecResponse;
        } else {
            inboundApduDescription = "Unhandled APDU: ";
            responseApdu = ISO7816_UNKNOWN_ERROR_RESPONSE;
        }

        Log.v(TAG, inboundApduDescription + Util.byteArrayToHex(commandApdu) +
                " / Response: " +Util.byteArrayToHex(responseApdu));

        return responseApdu;
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences prefs, String key) {
        Log.v(TAG, "onSharedPreferenceChanged: key="+ key);
        if (SWIPE_DATA_PREF_KEY.equals(key)) {
            String swipeData = prefs.getString(SWIPE_DATA_PREF_KEY, DEFAULT_SWIPE_DATA);
            configureReadRecResponse(swipeData);
        }
    }


    public void onCreate() {
        super.onCreate();
        Log.v(TAG, "onCreate");

        // Swipe data z preferencies
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
        String swipeData = prefs.getString(SWIPE_DATA_PREF_KEY, DEFAULT_SWIPE_DATA);
        configureReadRecResponse(swipeData);
        prefs.registerOnSharedPreferenceChangeListener(this);
    }


    @Override
    public void onDeactivated(int reason) {
        Log.v(TAG, "OnDeactivated"+String.valueOf(reason));

        Intent intent = new Intent(getApplicationContext(), Dashboard.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_BROUGHT_TO_FRONT | Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(intent);
    }
}
