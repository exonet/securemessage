# SecureMessage

[![Latest Version on Packagist][ico-version]][link-packagist]
[![Software License][ico-license]](LICENSE.md)
[![Total Downloads][ico-downloads]][link-downloads]

This package makes it possible to create (very) secure messages and store them in, for example, your database. A secure 
message is encrypted with a combination of three key 'parts':
- A "database key" - to be saved in a database.
- A "storage key" - to be stored on a disk/filesystem.
- A "verification code" - this code should _not_ be stored anywhere.

This way, if an attacker has access to the database, it still has only access to a small part of the complete key. The
same goes if an attacker has access to the file storage. Even if an attacker has access to the database _and_ the file
storage, a part of the complete key is still missing.

The verification code can be sent (securely) to the receiver of the secure message and with this code, it can decrypt the
message and read it.

## Requirements
This package requires PHP 8.2 or newer with the [sodium](https://www.php.net/manual/en/sodium.installation.php) extension enabled.
The optional Laravel integration supports Laravel 12 and 13. For PHP 7.3 up to 8.1, use version 1.x of this package.

## Install

Via Composer

``` bash
$ composer require exonet/securemessage
```

## Usage

```php
// Create the factory.
$secureMessageFactory = new Exonet\SecureMessage\Factory();
// Set the (application wide) meta key. This key must be exactly 10 characters long.
$secureMessageFactory->setMetaKey('djuyteb765');

// Create a new SecureMessage. Note: it is not encrypted yet! 
$secureMessage = $secureMessageFactory->make('Hello, world!');
// Encrypt the Secure Message.
$encryptedMessage = $secureMessage->encrypt();
```

Please see the `/docs` folder for complete documentation and additional examples.

## Upgrading from v1

Messages encrypted with v1 can still be decrypted with v2: the encrypted format and the key structure are unchanged.
Notable changes:

- PHP 8.2 or newer is required and the Laravel integration requires Laravel 12 or 13.
- The `sodium` extension is now a hard composer requirement (`ext-sodium`). On servers without the extension,
  `composer install` fails immediately instead of the package failing at the first encrypt.
- The whole code base is strictly typed (`declare(strict_types=1)`). Make sure you pass the documented types.
  In particular, check your published `config/secure_messages.php`: `hit_points` and `expires_in` must be real
  integers. A numeric string (for example from an `env()` call) was silently coerced by v1, but throws a
  `TypeError` in v2.
- The Laravel events (`DecryptionFailed`, `HitPointLimitReached`, `SecureMessageExpired`) now expose the secure
  message through a `public readonly` property `$secureMessage` (previously this property was private and inaccessible
  to listeners).
- A malformed encrypted message now throws a `DecryptException` when decrypting or validating a key, instead of
  failing with a PHP error. Code catching `TypeError` for this case should catch `DecryptException` instead.
- The migration class `CreateSecureMessagesTable` is now an anonymous class. The migration filename is unchanged,
  so existing installations are unaffected, but code referencing the class by name no longer works.

## Change log

Please see [releases][link-releases] for more information on what has changed recently.

## Testing

``` bash
$ composer test
```

## Contributing

Please see [CONTRIBUTING](.github/CONTRIBUTING.md) and [CODE_OF_CONDUCT](.github/CODE_OF_CONDUCT.md) for details.

## Security

If you discover any security related issues please email [development@exonet.nl](mailto:development@exonet.nl) instead of using 
the issue tracker.

## Credits

- [Exonet][link-author]
- [All Contributors][link-contributors]

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.

[ico-version]: https://img.shields.io/packagist/v/exonet/securemessage.svg?style=flat-square
[ico-license]: https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square
[ico-downloads]: https://img.shields.io/packagist/dt/exonet/securemessage.svg?style=flat-square

[link-packagist]: https://packagist.org/packages/exonet/securemessage
[link-downloads]: https://packagist.org/packages/exonet/securemessage
[link-author]: https://github.com/exonet
[link-releases]: https://github.com/exonet/securemessage/releases
[link-contributors]: ../../contributors
