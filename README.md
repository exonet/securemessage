# SecureMessage

[![Latest Version on Packagist][ico-version]][link-packagist]
[![Software License][ico-license]](LICENSE.md)
[![Build Status][ico-travis]][link-travis]
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
This package requires at least PHP 7.1 with the [libsodium](https://github.com/jedisct1/libsodium-php) extension.

## Install

Via Composer

``` bash
$ composer require exonet/securemessage
```

## Usage

```php
// Create the factory.
$secureMessageFactory = new Exonet\SecureMessage\Factory();
// Set the (application wide) meta key.
$secureMessageFactory->setMetaKey('A_10_random_characters_long_key.');

// Create a new SecureMessage. Note: it is not encrypted yet!
$secureMessage = $secureMessageFactory->make('Hello, world!');
// Encrypt the Secure Message.
$encryptedMessage = $secureMessage->encrypt();
```

Please see the `/docs` folder for complete documentation and additional examples.

## Change log

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Testing

``` bash
$ composer test
```

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) and [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md) for details.

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
[ico-travis]: https://img.shields.io/travis/exonet/securemessage/master.svg?style=flat-square
[ico-downloads]: https://img.shields.io/packagist/dt/exonet/securemessage.svg?style=flat-square

[link-packagist]: https://packagist.org/packages/exonet/securemessage
[link-travis]: https://travis-ci.org/exonet/securemessage
[link-downloads]: https://packagist.org/packages/exonet/securemessage
[link-author]: https://github.com/exonet
[link-contributors]: ../../contributors