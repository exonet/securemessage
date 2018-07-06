## Using the Laravel Factory

By using the Laravel adapter, using Secure Messages is even easier. Just register the service provider 
(`\Exonet\SecureMessage\Laravel\Providers\SecureMessageServiceProvider`) in your `config/app.php` and run 
`php artisan migrate` to create the necessary database tables. In your `.env` you can specify `SECURE_MESSAGE_META_KEY`
that will hold the encryption key for the meta data. This must be a string of 32 characters.

### Creating a secure message
By using the provided Facade, it is very easy to create a new secure message:

```php
$encryptedMessage = \SecureMessage::encrypt('Hello, world!');
```

By calling the `encrypt` method, the following things will happen:
- A secure message is created and encrypted.
- The secure message is stored in the database, along with the encrypted metadata and database key (by using the default Laravel encryption).
- A file is created with the (also encrypted) storage key.
- The original content, the database key and the storage key are removed from the Secure Message.
- The secure message is returned, containing the encrypted data and the verification code.

You can use `$encryptedMessage->getVerificationCode()` in the rest of your application logic, for example by emailing it
to a customer. 

> To make things even more secure, _never_ send the Secure Message ID and the verification code together!

### Decrypting a secure message
```php
// To get only the contents:
$decrypted = SecureMessage::decrypt('SECUREMESSAGEID','verificationCode');

// To get the complete Secure Message class:
$decryptedMessage = SecureMessage::decryptMessage('SECUREMESSAGEID','verificationCode');
```

- If the wrong verification code is entered a `DecryptException` is thrown and a `DecryptionFailed` event is fired.
- If the number of hit points is reached a `HitPointLimitReachedException` is thrown and a `HitPointLimitReached` event is fired.
- If the secure message is expired an `ExpiredException` is thrown and a `SecureMessageExpired` event is fired.

In all of these cases the hit points number is decreased by 1 and the secure message meta is updated in the database. If
the number of hit points reaches 0, the hit point limit is reached.

> Both the HitPointLimitReachedException and ExpiredException are extending the DecryptException.

### Keeping your app clean
To remove all expired secure messages and/or secure messages where the hit point limit is reached, you can execute the
following command to clean up the database and file storage:

```bash
php artisan secure_message:housekeeping
```
