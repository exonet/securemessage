<?php

declare(strict_types=1);

namespace Exonet\SecureMessage\Tests;

use Exonet\SecureMessage\Crypto;
use Exonet\SecureMessage\Exceptions\DecryptException;
use Exonet\SecureMessage\Exceptions\ExpiredException;
use Exonet\SecureMessage\Exceptions\HitPointLimitReachedException;
use Exonet\SecureMessage\Exceptions\InvalidKeyLengthException;
use Exonet\SecureMessage\SecureMessage;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
class CryptoTest extends TestCase
{
    public function testEncrypt(): void
    {
        $crypto = new Crypto();
        $secureMessage = new SecureMessage();
        $secureMessage->setMetaKey('metaKey___');
        $secureMessage->setStorageKey('storageKey_');
        $secureMessage->setVerificationCode('1234567890');
        $secureMessage->setDatabaseKey('databaseKey');
        $secureMessage->setContent('Unit Test');
        $secureMessage->setHitPoints(3);
        // This message will expire at Wednesday 23 June 2121 19:11:12 UTC
        $secureMessage->setExpiresAt(4823435472);

        $encrypted = $crypto->encrypt($secureMessage);

        // Validate the encrypted content, by decrypting it.
        $encryptedContentArray = json_decode(base64_decode($encrypted->getEncryptedContent(), true), true);
        $this->assertCount(2, $encryptedContentArray);
        $content = sodium_crypto_secretbox_open(
            base64_decode($encryptedContentArray[1], true),
            base64_decode($encryptedContentArray[0], true),
            'databaseKeystorageKey_1234567890'
        );
        $this->assertSame('Unit Test', $content);

        // Validate the encrypted meta, by decrypting it.
        $encryptedMetaArray = json_decode(base64_decode($encrypted->getEncryptedMeta(), true), true);
        $this->assertCount(2, $encryptedMetaArray);
        $metaArray = json_decode(sodium_crypto_secretbox_open(
            base64_decode($encryptedMetaArray[1], true),
            base64_decode($encryptedMetaArray[0], true),
            'databaseKeystorageKey_metaKey___'
        ), true);

        $this->assertSame(3, $metaArray['hit_points']);
        $this->assertSame(4823435472, $metaArray['expires_at']);
    }

    public function testEncryptInvalidKeyLength(): void
    {
        $crypto = new Crypto();
        $secureMessage = new SecureMessage();
        $secureMessage->setMetaKey('metaKey___');
        $secureMessage->setStorageKey('a');
        $secureMessage->setVerificationCode('b');
        $secureMessage->setDatabaseKey('c');
        $secureMessage->setContent('Unit Test');
        $secureMessage->setHitPoints(1337);
        $secureMessage->setExpiresAt(10);

        $this->expectException(InvalidKeyLengthException::class);

        $crypto->encrypt($secureMessage);
    }

    public function testEncryptInvalidMetaKeyLength(): void
    {
        $crypto = new Crypto();
        $secureMessage = new SecureMessage();
        $secureMessage->setMetaKey('a');
        $secureMessage->setStorageKey('storageKey_');
        $secureMessage->setVerificationCode('1234567890');
        $secureMessage->setDatabaseKey('databaseKey');
        $secureMessage->setContent('Unit Test');
        $secureMessage->setHitPoints(1337);
        $secureMessage->setExpiresAt(10);

        $this->expectException(InvalidKeyLengthException::class);

        $crypto->encrypt($secureMessage);
    }

    public function testDecrypt(): void
    {
        $crypto = new Crypto();
        $secureMessage = new SecureMessage();
        $secureMessage->setMetaKey('metaKey___');
        $secureMessage->setStorageKey('storageKey_');
        $secureMessage->setVerificationCode('1234567890');
        $secureMessage->setDatabaseKey('databaseKey');
        $secureMessage->setEncryptedContent('WyJtQXQxbXdBN3daeUVEbUtXZlJhQUVsZUlOektCXC84Y1YiLCJxWGs2YUJHNHhrSk5tK2pWUk9pTXVVYVZkcVJhUmtrUzFBPT0iXQ==');
        // This meta data will expire at Wednesday 23 June 2121 19:11:12 UTC and has 3 hit points.
        $secureMessage->setEncryptedMeta('WyJoQTZMSVJKbmRFMlwvbnZyT0lYVk56UEpJS01QQW5Fd0siLCJuWkFWYXRCSXA5NU5jelFXcG5KSUYzTmxJeTNOZkVQdWRYVjFDTFgzdkdIS0FOTUFBXC9XS1RzN0NnempWRTRjaGdieFBpMDlZQ2w4PSJd');

        $decrypted = $crypto->decrypt($secureMessage);

        $this->assertSame('Unit Test', $decrypted->getContent());
        $this->assertSame(3, $decrypted->getHitPoints());
        $this->assertSame(4823435472, $decrypted->getExpiresAt());
        // Test that the encrypted data is removed.
        $this->assertNull($decrypted->getEncryptedMeta());
        $this->assertNull($decrypted->getEncryptedContent());
        // Test that the keys are removed.
        $this->assertNull($decrypted->getMetaKey());
        $this->assertNull($decrypted->getStorageKey());
        $this->assertNull($decrypted->getVerificationCode());
        $this->assertNull($decrypted->getDatabaseKey());
    }

    public function testDecryptSecureMessageIsExpired(): void
    {
        $crypto = new Crypto();
        $secureMessage = new SecureMessage();
        $secureMessage->setMetaKey('metaKey___');
        $secureMessage->setStorageKey('storageKey_');
        $secureMessage->setVerificationCode('1234567890');
        $secureMessage->setDatabaseKey('databaseKey');
        $secureMessage->setEncryptedContent('WyJpeVFVdXRYMHJTWmJoT0V1Q3ROTFE3SFBqOVIwVngxbSIsInpGbHdBQ0dDdThVeFg1STVEZlA3MFFvY1loYU5KeHpMZ3c9PSJd');
        $secureMessage->setEncryptedMeta('WyJnSWlBOVBxRVFsWWhcLzNkRmhRNThMNWVieVRtSG81TzkiLCIrMGtzbzQ5NmRwbHZwZGR0dXBxMjZiRkdlUHg0cUY5dXIzbEQwSDFIazZnR1wvZjVKMjJQMGNPTFdhY0xzVkc0b3FBPT0iXQ==');

        $this->expectException(ExpiredException::class);

        $crypto->decrypt($secureMessage);
    }

    public function testDecryptHitpointsReached(): void
    {
        $crypto = new Crypto();
        $secureMessage = new SecureMessage();
        $secureMessage->setMetaKey('metaKey___');
        $secureMessage->setStorageKey('storageKey_');
        $secureMessage->setVerificationCode('WrongKey__');
        $secureMessage->setDatabaseKey('databaseKey');
        $secureMessage->setEncryptedContent('WyJNZUxkN1dUMWk2N0NBK013VnhGNHhoNTRaSVFZdWtDbyIsIlJRclFPTTdJR1UxVnJMMndGSCsxOURwVDRySDhRcEphOWc9PSJd');
        // This meta data will expire at Wednesday 23 June 2021 19:11:12 UTC and has 1 hit point.
        $secureMessage->setEncryptedMeta('WyJcLzg3RXVwTW54Smx0R2ZhT2tEK2ZPVVUzQnRxQmxuc0IiLCJHaGV3ekljOVEweEhTVUxDSDJVRXM5OVV6bEdQSVo4SzMwOVcrZlJHMldhdTFqc2QxMTBtSTVzbVgzSDJLT0JJT0Z4XC9sMGpHdjlNPSJd');

        /*
         * Don't use `$this->expectException` here, but catch the exception. This way a test can be performed that the
         * meta is correctly updated.
         */
        $exceptionThrown = false;

        try {
            $crypto->decrypt($secureMessage);
        } catch (HitPointLimitReachedException $exception) {
            $exceptionThrown = true;

            // Check if the meta key is removed from the secure message and re-add it to decrypt the meta.
            $this->assertNull($exception->secureMessage->getMetaKey());
            $exception->secureMessage->setStorageKey('storageKey_');
            $exception->secureMessage->setDatabaseKey('databaseKey');
            $exception->secureMessage->setMetaKey('metaKey___');

            // Decrypt the meta from the exception to assert that the hit points are changed to 0 and the keys are unset.
            $decryptedMeta = $crypto->decryptMeta($exception->secureMessage);
            $this->assertSame(0, $decryptedMeta->getHitPoints());
        }

        $this->assertTrue($exceptionThrown);
    }

    public function testDecryptInvalidVerificationCode(): void
    {
        $crypto = new Crypto();
        $secureMessage = new SecureMessage();
        $secureMessage->setMetaKey('metaKey___');
        $secureMessage->setStorageKey('storageKey_');
        $secureMessage->setVerificationCode('WrongKey__');
        $secureMessage->setDatabaseKey('databaseKey');
        $secureMessage->setEncryptedContent('WyJtQXQxbXdBN3daeUVEbUtXZlJhQUVsZUlOektCXC84Y1YiLCJxWGs2YUJHNHhrSk5tK2pWUk9pTXVVYVZkcVJhUmtrUzFBPT0iXQ==');
        // This meta data will expire at Wednesday 23 June 2121 19:11:12 UTC and has 3 hit points.
        $secureMessage->setEncryptedMeta('WyJoQTZMSVJKbmRFMlwvbnZyT0lYVk56UEpJS01QQW5Fd0siLCJuWkFWYXRCSXA5NU5jelFXcG5KSUYzTmxJeTNOZkVQdWRYVjFDTFgzdkdIS0FOTUFBXC9XS1RzN0NnempWRTRjaGdieFBpMDlZQ2w4PSJd');

        /*
         * Don't use `$this->expectException` here, but catch the exception. This way a test can be performed that the
         * meta is correctly updated.
         */
        $exceptionThrown = false;

        try {
            $crypto->decrypt($secureMessage);
        } catch (DecryptException $exception) {
            $exceptionThrown = true;

            // Check if the meta key is removed from the secure message and re-add it to decrypt the meta.
            $this->assertNull($exception->secureMessage->getMetaKey());
            $exception->secureMessage->setStorageKey('storageKey_');
            $exception->secureMessage->setDatabaseKey('databaseKey');
            $exception->secureMessage->setMetaKey('metaKey___');

            // Decrypt the meta from the exception to assert that the hit points are changed to 2 and the keys are unset.
            $decryptedMeta = $crypto->decryptMeta($exception->secureMessage);
            $this->assertSame(2, $decryptedMeta->getHitPoints());
        }

        $this->assertTrue($exceptionThrown);
    }

    public function testEncryptDecryptBinaryContent(): void
    {
        $crypto = new Crypto();
        $binary = implode('', array_map('chr', range(0, 255))).random_bytes(1024 * 1024 + 1);

        $secureMessage = new SecureMessage();
        $secureMessage->setMetaKey('metaKey___');
        $secureMessage->setStorageKey('storageKey_');
        $secureMessage->setVerificationCode('1234567890');
        $secureMessage->setDatabaseKey('databaseKey');
        $secureMessage->setContent($binary);
        $secureMessage->setHitPoints(3);
        $secureMessage->setExpiresAt(time() + 3600);

        $decrypted = $crypto->decrypt($crypto->encrypt($secureMessage));

        $this->assertSame($binary, $decrypted->getContent());
    }

    public function testEncryptDecryptKeepsFileMeta(): void
    {
        $crypto = new Crypto();

        $secureMessage = new SecureMessage();
        $secureMessage->setMetaKey('metaKey___');
        $secureMessage->setStorageKey('storageKey_');
        $secureMessage->setVerificationCode('1234567890');
        $secureMessage->setDatabaseKey('databaseKey');
        $secureMessage->setContent("file\x00contents");
        $secureMessage->setHitPoints(3);
        $secureMessage->setExpiresAt(time() + 3600);
        $secureMessage->setFileName('report.pdf');
        $secureMessage->setMimeType('application/pdf');
        $secureMessage->setFileSize(13);

        $decrypted = $crypto->decrypt($crypto->encrypt($secureMessage));

        $this->assertSame("file\x00contents", $decrypted->getContent());
        $this->assertTrue($decrypted->isFile());
        $this->assertSame('report.pdf', $decrypted->getFileName());
        $this->assertSame('application/pdf', $decrypted->getMimeType());
        $this->assertSame(13, $decrypted->getFileSize());
    }

    public function testFileMetaSurvivesFailedDecrypt(): void
    {
        $crypto = new Crypto();

        $secureMessage = new SecureMessage();
        $secureMessage->setMetaKey('metaKey___');
        $secureMessage->setStorageKey('storageKey_');
        $secureMessage->setVerificationCode('1234567890');
        $secureMessage->setDatabaseKey('databaseKey');
        $secureMessage->setContent('file contents');
        $secureMessage->setHitPoints(3);
        $secureMessage->setExpiresAt(time() + 3600);
        $secureMessage->setFileName('report.pdf');

        $encrypted = $crypto->encrypt($secureMessage);
        $encrypted->setVerificationCode('WrongKey__');

        $exceptionThrown = false;

        try {
            $crypto->decrypt($encrypted);
        } catch (DecryptException $exception) {
            $exceptionThrown = true;

            // Re-add the keys to decrypt the updated meta from the exception.
            $exception->secureMessage->setStorageKey('storageKey_');
            $exception->secureMessage->setDatabaseKey('databaseKey');
            $exception->secureMessage->setMetaKey('metaKey___');

            $decryptedMeta = $crypto->decryptMeta($exception->secureMessage);

            // The hit points are reduced, but the file meta is untouched.
            $this->assertSame(2, $decryptedMeta->getHitPoints());
            $this->assertTrue($decryptedMeta->isFile());
            $this->assertSame('report.pdf', $decryptedMeta->getFileName());
        }

        $this->assertTrue($exceptionThrown);
    }

    public function testValidateEncryptionKeyCorrectKey(): void
    {
        $crypto = new Crypto();
        $secureMessage = new SecureMessage();
        $secureMessage->setMetaKey('metaKey___');
        $secureMessage->setStorageKey('storageKey_');
        $secureMessage->setVerificationCode('1234567890');
        $secureMessage->setDatabaseKey('databaseKey');
        $secureMessage->setEncryptedContent('WyJtQXQxbXdBN3daeUVEbUtXZlJhQUVsZUlOektCXC84Y1YiLCJxWGs2YUJHNHhrSk5tK2pWUk9pTXVVYVZkcVJhUmtrUzFBPT0iXQ==');
        // This meta data will expire at Wednesday 23 June 2121 19:11:12 UTC and has 3 hit points.
        $secureMessage->setEncryptedMeta('WyJoQTZMSVJKbmRFMlwvbnZyT0lYVk56UEpJS01QQW5Fd0siLCJuWkFWYXRCSXA5NU5jelFXcG5KSUYzTmxJeTNOZkVQdWRYVjFDTFgzdkdIS0FOTUFBXC9XS1RzN0NnempWRTRjaGdieFBpMDlZQ2w4PSJd');

        $this->assertTrue($crypto->validateEncryptionKey($secureMessage));
    }

    public function testValidateEncryptionKeyIncorrectKey(): void
    {
        $crypto = new Crypto();
        $secureMessage = new SecureMessage();
        $secureMessage->setMetaKey('metaKey___');
        $secureMessage->setStorageKey('storageKey_');
        // This verification code is wrong.
        $secureMessage->setVerificationCode('1234567899');
        $secureMessage->setDatabaseKey('databaseKey');
        $secureMessage->setEncryptedContent('WyJtQXQxbXdBN3daeUVEbUtXZlJhQUVsZUlOektCXC84Y1YiLCJxWGs2YUJHNHhrSk5tK2pWUk9pTXVVYVZkcVJhUmtrUzFBPT0iXQ==');
        // This meta data will expire at Wednesday 23 June 2121 19:11:12 UTC and has 3 hit points.
        $secureMessage->setEncryptedMeta('WyJoQTZMSVJKbmRFMlwvbnZyT0lYVk56UEpJS01QQW5Fd0siLCJuWkFWYXRCSXA5NU5jelFXcG5KSUYzTmxJeTNOZkVQdWRYVjFDTFgzdkdIS0FOTUFBXC9XS1RzN0NnempWRTRjaGdieFBpMDlZQ2w4PSJd');

        $this->assertFalse($crypto->validateEncryptionKey($secureMessage));
    }

    public function testValidateEncryptionKeyKeyTooShort(): void
    {
        $crypto = new Crypto();
        $secureMessage = new SecureMessage();
        $secureMessage->setMetaKey('metaKey___');
        $secureMessage->setStorageKey('storageKey_');
        // This verification code is too short.
        $secureMessage->setVerificationCode('12345678');
        $secureMessage->setDatabaseKey('databaseKey');
        $secureMessage->setEncryptedContent('WyJtQXQxbXdBN3daeUVEbUtXZlJhQUVsZUlOektCXC84Y1YiLCJxWGs2YUJHNHhrSk5tK2pWUk9pTXVVYVZkcVJhUmtrUzFBPT0iXQ==');
        // This meta data will expire at Wednesday 23 June 2121 19:11:12 UTC and has 3 hit points.
        $secureMessage->setEncryptedMeta('WyJoQTZMSVJKbmRFMlwvbnZyT0lYVk56UEpJS01QQW5Fd0siLCJuWkFWYXRCSXA5NU5jelFXcG5KSUYzTmxJeTNOZkVQdWRYVjFDTFgzdkdIS0FOTUFBXC9XS1RzN0NnempWRTRjaGdieFBpMDlZQ2w4PSJd');

        $this->assertFalse($crypto->validateEncryptionKey($secureMessage));
    }

    public function testDecryptMeta(): void
    {
        $crypto = new Crypto();
        $secureMessage = new SecureMessage();
        $secureMessage->setMetaKey('metaKey___');
        $secureMessage->setStorageKey('storageKey_');
        $secureMessage->setVerificationCode('1234567890');
        $secureMessage->setDatabaseKey('databaseKey');
        $secureMessage->setEncryptedContent('WyJtQXQxbXdBN3daeUVEbUtXZlJhQUVsZUlOektCXC84Y1YiLCJxWGs2YUJHNHhrSk5tK2pWUk9pTXVVYVZkcVJhUmtrUzFBPT0iXQ==');
        // This meta data will expire at Wednesday 23 June 2121 19:11:12 UTC and has 3 hit points.
        $secureMessage->setEncryptedMeta('WyJoQTZMSVJKbmRFMlwvbnZyT0lYVk56UEpJS01QQW5Fd0siLCJuWkFWYXRCSXA5NU5jelFXcG5KSUYzTmxJeTNOZkVQdWRYVjFDTFgzdkdIS0FOTUFBXC9XS1RzN0NnempWRTRjaGdieFBpMDlZQ2w4PSJd');

        $decrypted = $crypto->decryptMeta($secureMessage);

        $this->assertSame(3, $decrypted->getHitPoints());
        $this->assertSame(4823435472, $decrypted->getExpiresAt());
        // Test that the encrypted meta is removed, but the content is still encrypted.
        $this->assertNull($decrypted->getEncryptedMeta());
        $this->assertNull($decrypted->getContent());
        $this->assertNotNull($decrypted->getEncryptedContent());
    }

    public function testDecryptMetaInvalidMetaKey(): void
    {
        $crypto = new Crypto();
        $secureMessage = new SecureMessage();
        $secureMessage->setMetaKey('invalid_________________________');
        $secureMessage->setStorageKey('storageKey_');
        $secureMessage->setVerificationCode('1234567890');
        $secureMessage->setDatabaseKey('databaseKey');
        $secureMessage->setEncryptedContent('WyJtQXQxbXdBN3daeUVEbUtXZlJhQUVsZUlOektCXC84Y1YiLCJxWGs2YUJHNHhrSk5tK2pWUk9pTXVVYVZkcVJhUmtrUzFBPT0iXQ==');
        // This meta data will expire at Wednesday 23 June 2121 19:11:12 UTC and has 3 hit points.
        $secureMessage->setEncryptedMeta('WyJoQTZMSVJKbmRFMlwvbnZyT0lYVk56UEpJS01QQW5Fd0siLCJuWkFWYXRCSXA5NU5jelFXcG5KSUYzTmxJeTNOZkVQdWRYVjFDTFgzdkdIS0FOTUFBXC9XS1RzN0NnempWRTRjaGdieFBpMDlZQ2w4PSJd');

        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage('Unable to or failed to decrypt the meta data.');
        $crypto->decryptMeta($secureMessage);
    }
}
