<?php

declare(strict_types=1);

use Exonet\SecureMessage\Factory;

require __DIR__.'/../../vendor/autoload.php';

// Create a small binary example file.
$examplePath = tempnam(sys_get_temp_dir(), 'securemessage_example');
file_put_contents($examplePath, "\x89PNG\r\n\x1A\n".random_bytes(256));

// Create the factory.
$secureMessageFactory = new Factory();
// Set the (application wide) meta key. (Don't use this simple key in production!)
$secureMessageFactory->setMetaKey('0123456789');

// Create a new SecureMessage from the file and encrypt it. The file name, mime type and size are
// stored in the encrypted meta data.
$secureMessage = $secureMessageFactory->makeFile($examplePath, fileName: 'example.bin');
$encryptedMessage = $secureMessage->encrypt();

echo '---[ ENCRYPTED FILE MESSAGE ]---'."\n";
echo sprintf("ID: %s\n", $encryptedMessage->getId());
echo sprintf("Verification code: %s\n", $encryptedMessage->getVerificationCode());
echo sprintf("Encrypted size: %d bytes\n", strlen((string) $encryptedMessage->getEncryptedContent()));

echo "\n";

/*
 * To keep things simple for this example, the encrypted data and keys are reused directly. In a real
 * world application you'll have to store the keys at their three separate locations, and read them
 * back when the receiver enters the verification code.
 */
$decryptedMessage = $secureMessageFactory->decrypt($encryptedMessage);

echo '---[ DECRYPTED FILE MESSAGE ]---'."\n";
echo sprintf("Is file: %s\n", $decryptedMessage->isFile() ? 'yes' : 'no');
echo sprintf("File name: %s\n", $decryptedMessage->getFileName());
echo sprintf("Mime type: %s\n", $decryptedMessage->getMimeType());
echo sprintf("File size: %d bytes\n", $decryptedMessage->getFileSize());
echo sprintf(
    "Contents intact: %s\n",
    $decryptedMessage->getContent() === file_get_contents($examplePath) ? 'yes' : 'no'
);

unlink($examplePath);
