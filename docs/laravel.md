## Using the Laravel Factory

### Installation
- Run `composer require exonet/securemessage`.
- If you use Laravel 5.5 or newer, the required ServiceProvider is automatically registered. For older Laravel versions you need to register the service provider `\Exonet\SecureMessage\Laravel\Providers\SecureMessageServiceProvider::class` in your `config/app.php`.
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

In all of these three cases the hit points number is decreased by 1 and the secure message meta is updated in the database. If
the number of hit points reaches 0, the hit point limit is reached and the message can no longer be decrypted.

> Both the HitPointLimitReachedException and ExpiredException are extending the DecryptException.

### Keeping your app clean
To remove all expired secure messages and/or secure messages where the hit point limit is reached, you can execute the
following command to clean up the database and file storage:

```bash
php artisan secure_message:housekeeping
```
