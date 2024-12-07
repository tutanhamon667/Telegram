package org.telegram.messenger;

public class GPGMessageProcessor {
    private static volatile GPGMessageProcessor[] Instance = new GPGMessageProcessor[UserConfig.MAX_ACCOUNT_COUNT];
    private final int currentAccount;
    private final GPGEncryptionHelper gpgHelper;

    public static GPGMessageProcessor getInstance(int num) {
        GPGMessageProcessor localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (GPGMessageProcessor.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    Instance[num] = localInstance = new GPGMessageProcessor(num);
                }
            }
        }
        return localInstance;
    }

    public GPGMessageProcessor(int num) {
        currentAccount = num;
        gpgHelper = GPGEncryptionHelper.getInstance(currentAccount);
    }

    public String processOutgoingMessage(String message, long dialogId) {
        if (message == null || message.isEmpty() || !SharedConfig.isGPGEnabledForChat(dialogId)) {
            return message;
        }

        try {
            SharedConfig.ChatGPGSettings settings = SharedConfig.getGPGSettingsForChat(dialogId);
            if (settings != null && settings.publicKey != null) {
                return gpgHelper.encryptMessage(message, settings.publicKey);
            }
        } catch (Exception e) {
            FileLog.e("GPG encryption failed", e);
        }
        return message;
    }

    public String processIncomingMessage(String message, long dialogId) {
        if (message == null || !message.startsWith("-----BEGIN PGP MESSAGE-----") || 
            !SharedConfig.isGPGEnabledForChat(dialogId)) {
            return message;
        }

        try {
            SharedConfig.ChatGPGSettings settings = SharedConfig.getGPGSettingsForChat(dialogId);
            if (settings != null && settings.privateKey != null && settings.passphrase != null) {
                return gpgHelper.decryptMessage(message, settings.privateKey, settings.passphrase);
            }
        } catch (Exception e) {
            FileLog.e("GPG decryption failed", e);
        }
        return message;
    }
}
