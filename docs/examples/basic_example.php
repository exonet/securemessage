<?php

require __DIR__.'/../../vendor/autoload.php';

// Create the factory.
$secureMessageFactory = new Exonet\SecureMessage\Factory();
// Set the (application wide) meta key. (Don't use this simple key in production!)
$secureMessageFactory->setMetaKey('0123456789');

// Create a new SecureMessage. Note: it is not encrypted yet!
$secureMessage = $secureMessageFactory->make('Hello, world!');
// Encrypt the Secure Message.
$encryptedMessage = $secureMessage->encrypt();

/*
 * At this point if this was a real application you should store the encrypted content, encrypted meta and the
 * database key to a database. The storageKey must be stored in a file on a secure file on disk and the verification
 * code should be returned to the user. After storing all the data, `$encryptedMessage->wipeKeysFromMemory()` must
 * be called to wipe all keys from memory.
 */

echo "\n\n";

/*
 * You can give the ID and VerificationCode to your user. The database and storage key are  displayed here for
 * demonstration purposes, but in a real-world application the user doesn't need to know about them.
 */
echo '---[ ENCRYPTED MESSAGE DATA ]---'."\n";
echo sprintf("ID: %s\n", $encryptedMessage->getId());
echo sprintf("Database key: %s\n", base64_encode($encryptedMessage->getDatabaseKey()));
echo sprintf("Storage key: %s\n", base64_encode($encryptedMessage->getStorageKey()));
echo sprintf("Verification code: %s\n", $encryptedMessage->getVerificationCode());

echo "\n\n";

// Getting the meta data only requires the meta key to be set.
echo '---[ DECRYPTED META DATA ]---'."\n";
$decryptedMeta = $encryptedMessage->getMeta();
echo sprintf("Remaining hitpoints: %s\n", $decryptedMeta['hit_points']);
echo sprintf("Expire date: %s\n", date('Y-m-d H:i', $decryptedMeta['expires_at']));

echo "\n\n";

/*
 * To keep things simple for this example, the encrypted data and keys are retrieved directly from the encrypted message.
 * In a real world application, you'll have to read them from the database, file on disk and the user input (verification
 * code).
 */
echo '---[ DECRYPTED MESSAGE ]---'."\n";
$decryptedMessage = $encryptedMessage
    ->setEncryptedContent($encryptedMessage->getEncryptedContent())
    ->setEncryptedMeta($encryptedMessage->getEncryptedMeta())
    ->setDatabaseKey($encryptedMessage->getDatabaseKey())
    ->setStorageKey($encryptedMessage->getStorageKey())
    ->setVerificationCode($encryptedMessage->getVerificationCode());

echo sprintf("Message: %s\n", $secureMessageFactory->decrypt($decryptedMessage)->getContent());
