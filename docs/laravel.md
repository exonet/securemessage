## Using the Laravel Factory

### Installation
- Run `composer require exonet/securemessage`.
- The required ServiceProvider is automatically registered via package discovery.
- In your `.env` file add the following key `SECURE_MESSAGE_META_KEY`. Give it an alphanumeric 10 characters long [random](https://www.random.org/strings/?num=1&len=10&digits=on&upperalpha=on&loweralpha=on&unique=on&format=html&rnd=new) value. 
- In your `config/filesystems.php` file, add a new storage disk with the name `secure_messages`. For example: `'secure_messages' => ['driver' => 'local', 'root' => storage_path('/secure_messages')],`.
- (optional) If you'd like to change the storage disk name, default hit points or default expire date, run `php artisan vendor:publish --provider="Exonet\\SecureMessage\\Laravel\\Providers\\SecureMessageServiceProvider" --tag=config` to get the config file to edit those settings.

### Creating a secure message
By using the provided Facade, it is very easy to create a new secure message:

```php
$encryptedMessage = \SecureMessage::encrypt('Hello, world!');
```

By calling the `encrypt` method, the following things will happen:
- A secure message is created and encrypted.
- The secure message is stored in the database, along with the encrypted metadata and database key (encrypted a second time with the default Laravel encryption).
- A file is created with the (also double encrypted) storage key.
- The original content, the database key and the storage key are removed from the Secure Message.
- The secure message is returned, containing the encrypted data and the verification code.

You can use `$encryptedMessage->getId()` and `$encryptedMessage->getVerificationCode()` in the rest of your application 
logic, for example by sending it to a customer. 

> To make things even more secure, _never_ send the Secure Message ID and the verification code together!

### Decrypting a secure message
```php
// To get only the contents:
$decrypted = SecureMessage::decrypt('SECUREMESSAGEID','verificationCode');

// To get the complete Secure Message class (containing also the meta data etc.):
$decryptedMessage = SecureMessage::decryptMessage('SECUREMESSAGEID','verificationCode');
```

- If the wrong verification code is entered a `DecryptException` is thrown and a `DecryptionFailed` event is fired.
- If the number of hit points is reached a `HitPointLimitReachedException` is thrown and a `HitPointLimitReached` event is fired.
- If the secure message is expired an `ExpiredException` is thrown and a `SecureMessageExpired` event is fired.
- If the storage key file or the file blob can not be found a `MissingContentException` is thrown and a `DecryptionFailed` event is fired. The verification code was not checked, so no hit point is used.

In the first three cases the hit points number is decreased by 1 and the secure message meta is updated in the database. If
the number of hit points reaches 0, the hit point limit is reached and the message can no longer be decrypted.

> The HitPointLimitReachedException, ExpiredException and MissingContentException all extend the DecryptException.

### Keeping your app clean
To remove all expired secure messages and/or secure messages where the hit point limit is reached, you can execute the
following command to clean up the database and file storage:

```bash
php artisan secure_message:housekeeping
```

## Files as secure messages

### Setup
- In your `config/filesystems.php`, add a storage disk with the name `secure_messages_files`. Use a disk that is
  separate from the `secure_messages` (storage key) disk — and ideally separate from the database host — so that no
  single compromised store holds multiple parts of the encryption key material. With the default local driver:
  `'secure_messages_files' => ['driver' => 'local', 'root' => storage_path('/secure_messages_files')],`
- Upgrading from a version before 2.1? Run `php artisan migrate` — the package ships a migration that makes the
  `content` column nullable. Installations that only use text messages don't need to configure the files disk: it is
  resolved lazily, only when file messages are used.

### Encrypting a file

```php
// From a path:
$encryptedMessage = \SecureMessage::encryptFile('/path/to/report.pdf');

// Or directly from an upload; the original client file name is stored automatically:
$encryptedMessage = \SecureMessage::encryptFile($request->file('attachment'));
```

The encrypted file contents are stored (double encrypted, like everything else) on the files disk; the database
record only holds the keys and meta data. The maximum file size is limited by the `max_file_size` config setting
(default 10 MB) because files are encrypted in memory and the stored blob is roughly three times the original file
size.

> **Note:** the source file itself is left untouched — `encryptFile()` only *reads* it. For uploads this is fine
> (PHP removes the temporary upload file at the end of the request), but if your application first writes a file to
> disk and then stores it as a secure message, deleting the unencrypted original afterwards is the responsibility of
> your application.

### Decrypting and downloading a file

`decryptMessage` works for file messages exactly as it does for text messages, including hit points, expiry and the
events. To offer the file as a download:

```php
$message = \SecureMessage::decryptMessage('SECUREMESSAGEID', 'verificationCode');

return response($message->getContent(), 200, [
    'Content-Type' => $message->getMimeType() ?? 'application/octet-stream',
    'Content-Disposition' => 'attachment; filename="'.addslashes($message->getFileName()).'"',
]);
```

> **Note:** the file meta data (including the file name!) is part of the meta and can be read server side via
> `SecureMessage::getMeta()` *without* the verification code. Don't show the file name to visitors before they have
> entered a valid verification code, unless that is intended.
