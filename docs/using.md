## Creating a Secure Message

By using the provided factory it is pretty easy to create a new secure message:

```php
// Create the factory.
$secureMessageFactory = new \Exonet\SecureMessage\Factory();
// Set the (application wide) meta key.
$secureMessageFactory->setMetaKey('djuyteb765');

// Create a new SecureMessage. Note: it is not encrypted yet!
$secureMessage = $secureMessageFactory->make('Hello, world!');
// Encrypt the Secure Message.
$encryptedMessage = $secureMessage->encrypt();
```

`$encryptedMessage` now contains the encrypted data, including the three keys that are needed to decrypt it. Make sure that
after storing them, you call `$encryptedMessage->wipeKeysFromMemory()` to securely erase the keys.

The `meta key` is a string of 10 characters that is used when encrypting the meta data in combination with the database
and storage key. This can be the same key for each secure message (because of the use of the database and storage
keys the complete key used for encryption is never the same) or per secure message. However, if you're using a meta 
key per secure message, please note that you must store it somewhere or that you can recreate it, because it is necessary 
for every decrypt/validation action.

## Decrypting a Secure Message

Assuming you've the correct keys:

```php
// Create the factory.
$secureMessageFactory = new Exonet\SecureMessage\Factory();
// Set the (application wide) meta key.
$secureMessageFactory->setMetaKey('djuyteb765');

$secureMessage = new \Exonet\SecureMessage\SecureMessage();
$secureMessage->setEncryptedContent('[the encrypted content]');
$secureMessage->setEncryptedMeta('[the encrypted meta data]');
$secureMessage->setDatabaseKey('TheDatabaseKey');
$secureMessage->setStorageKey('TheStorageKey');
$secureMessage->setVerificationCode('a1bc2ef4xy');

$decryptedMessage = $secureMessageFactory->decrypt($secureMessage);
```

## Files as Secure Messages

A file can be stored as a secure message: the file contents become the (binary safe) message content and the file
name, mime type and file size travel along in the encrypted meta data.

```php
$secureMessageFactory = new \Exonet\SecureMessage\Factory();
$secureMessageFactory->setMetaKey('djuyteb765');

// Create a SecureMessage from a file. Note: it is not encrypted yet!
$secureMessage = $secureMessageFactory->makeFile('/path/to/report.pdf');
$encryptedMessage = $secureMessage->encrypt();
```

Decrypting works exactly the same as for text messages. After decrypting, the file meta data is available:

```php
$decrypted = $secureMessageFactory->decrypt($secureMessage);

$decrypted->isFile();        // true
$decrypted->getFileName();   // 'report.pdf'
$decrypted->getMimeType();   // 'application/pdf'
$decrypted->getFileSize();   // The size in bytes.
$decrypted->getContent();    // The raw file contents.
```

Some things to keep in mind:

- Files are encrypted **in memory**, so this is meant for small files (documents, images). The encoded, encrypted
  message is roughly 1.8 times the original file size.
- The file name must be valid UTF-8 (the meta data is JSON encoded). For files with a non-UTF-8 name, pass an
  explicit name: `$factory->makeFile($path, fileName: 'sanitized-name.bin')`. The same applies to files on
  temporary paths (such as uploads), where the base name of the path is meaningless.
- Mime type detection requires the `fileinfo` extension; without it, `application/octet-stream` is stored.
- **The source file itself is left untouched.** `makeFile()` only *reads* the file: the original, unencrypted file
  stays at its path. If the goal is that the contents only exist as a secure message, deleting (or shredding) the
  source file after encrypting is the responsibility of your application.
