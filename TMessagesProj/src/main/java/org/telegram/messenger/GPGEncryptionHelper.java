package org.telegram.messenger;

import android.util.Base64;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import java.io.*;
import java.security.*;
import java.util.Iterator;

public class GPGEncryptionHelper extends BaseController {
    private static volatile GPGEncryptionHelper[] Instance = new GPGEncryptionHelper[UserConfig.MAX_ACCOUNT_COUNT];
    private PGPPublicKeyRingCollection pubKeys;
    private PGPSecretKeyRingCollection secretKeys;

    public static GPGEncryptionHelper getInstance(int num) {
        GPGEncryptionHelper localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (GPGEncryptionHelper.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    Instance[num] = localInstance = new GPGEncryptionHelper(num);
                }
            }
        }
        return localInstance;
    }

    public GPGEncryptionHelper(int num) {
        super(num);
        Security.addProvider(new BouncyCastleProvider());
    }

    // Simple method to encrypt text messages only
    public String encryptMessage(String message, String recipientPublicKey) throws Exception {
        if (message == null || message.isEmpty()) {
            return message;
        }

        PGPPublicKey pubKey = readPublicKey(recipientPublicKey);
        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(encOut);

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
            new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(new SecureRandom())
                .setProvider("BC")
        );

        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pubKey).setProvider("BC"));
        OutputStream encryptedOut = encGen.open(armorOut, message.getBytes().length);
        encryptedOut.write(message.getBytes());
        encryptedOut.close();
        armorOut.close();

        return encOut.toString("UTF-8");
    }

    // Simple method to decrypt text messages only
    public String decryptMessage(String encryptedMessage, String privateKey, String passphrase) throws Exception {
        if (encryptedMessage == null || !encryptedMessage.startsWith("-----BEGIN PGP MESSAGE-----")) {
            return encryptedMessage;
        }

        PGPPrivateKey pgpPrivKey = readPrivateKey(privateKey, passphrase);
        ByteArrayInputStream encIn = new ByteArrayInputStream(encryptedMessage.getBytes());
        InputStream decryptedData = new ArmoredInputStream(encIn);

        PGPObjectFactory pgpFactory = new PGPObjectFactory(decryptedData, new JcaKeyFingerprintCalculator());
        Object obj = pgpFactory.nextObject();
        
        if (obj instanceof PGPEncryptedDataList) {
            PGPEncryptedDataList encList = (PGPEncryptedDataList) obj;
            Iterator<?> encObjs = encList.getEncryptedDataObjects();
            
            while (encObjs.hasNext()) {
                Object encObj = encObjs.next();
                if (encObj instanceof PGPPublicKeyEncryptedData) {
                    PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encObj;
                    InputStream clear = encData.getDataStream(
                        new JcePublicKeyDataDecryptorFactoryBuilder()
                            .setProvider("BC")
                            .build(pgpPrivKey)
                    );
                    
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    int ch;
                    while ((ch = clear.read()) >= 0) {
                        out.write(ch);
                    }
                    return new String(out.toByteArray());
                }
            }
        }
        throw new IllegalArgumentException("Message is not a valid PGP encrypted message");
    }

    private PGPPublicKey readPublicKey(String publicKeyString) throws Exception {
        InputStream keyIn = new ByteArrayInputStream(publicKeyString.getBytes());
        PGPPublicKeyRing publicKeyRing = new PGPPublicKeyRing(
            PGPUtil.getDecoderStream(keyIn),
            new JcaKeyFingerprintCalculator()
        );
        return publicKeyRing.getPublicKey();
    }

    private PGPPrivateKey readPrivateKey(String privateKeyString, String passphrase) throws Exception {
        InputStream keyIn = new ByteArrayInputStream(privateKeyString.getBytes());
        PGPSecretKeyRing secretKeyRing = new PGPSecretKeyRing(
            PGPUtil.getDecoderStream(keyIn),
            new JcaKeyFingerprintCalculator()
        );
        
        PGPSecretKey secretKey = secretKeyRing.getSecretKey();
        return secretKey.extractPrivateKey(
            new JcePBESecretKeyDecryptorBuilder()
                .setProvider("BC")
                .build(passphrase.toCharArray())
        );
    }
}
