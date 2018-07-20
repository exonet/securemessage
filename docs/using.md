## Creating a Secure Message

By using the provided factory it is pretty easy to create a new secure message:

```php
// Create the factory.
$secureMessageFactory = new \Exonet\SecureMessage\Factory();
// Set the (application wide) meta key.
$secureMessageFactory->setMetaKey('djuyteb765d');

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
$secureMessageFactory->setMetaKey('djuyteb765d');

$secureMessage = new \Exonet\SecureMessage\SecureMessage();
$secureMessage->setEncryptedContent('[the encrypted content]');
$secureMessage->setEncryptedMeta('[the encrypted meta data]');
$secureMessage->setDatabaseKey('TheDatabaseKey');
$secureMessage->setStorageKey('TheStorageKey');
$secureMessage->setVerificationCode('a1bc2ef4xy');

$decryptedMessage = $secureMessageFactory->decrypt($secureMessage);
```
