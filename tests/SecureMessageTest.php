<?php

declare(strict_types=1);

namespace Exonet\SecureMessage\Tests;

use Exonet\SecureMessage\Exceptions\InvalidFileException;
use Exonet\SecureMessage\SecureMessage;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
class SecureMessageTest extends TestCase
{
    public function testWipeKeysFromMemory(): void
    {
        $secureMessage = new SecureMessage();
        $secureMessage->setDatabaseKey('abc');
        $secureMessage->setStorageKey('abc');
        $secureMessage->setMetaKey('abc');
        $secureMessage->setVerificationCode('abc');

        $secureMessage->wipeKeysFromMemory(false);

        $this->assertNull($secureMessage->getDatabaseKey());
        $this->assertNull($secureMessage->getStorageKey());
        $this->assertNull($secureMessage->getMetaKey());
        $this->assertNotNull($secureMessage->getVerificationCode());

        $secureMessage->wipeKeysFromMemory(true);

        $this->assertNull($secureMessage->getDatabaseKey());
        $this->assertNull($secureMessage->getStorageKey());
        $this->assertNull($secureMessage->getMetaKey());
        $this->assertNull($secureMessage->getVerificationCode());
    }

    public function testWipeContentFromMemory(): void
    {
        $secureMessage = new SecureMessage();
        $secureMessage->setContent('abc');

        $secureMessage->wipeContentFromMemory();
        $this->assertNull($secureMessage->getContent());
    }

    public function testWipeEncryptedContentFromMemory(): void
    {
        $secureMessage = new SecureMessage();
        $secureMessage->setEncryptedContent('abc');

        $secureMessage->wipeEncryptedContentFromMemory();
        $this->assertNull($secureMessage->getEncryptedContent());
    }

    public function testWipeEncryptedMetaFromMemory(): void
    {
        $secureMessage = new SecureMessage();
        $secureMessage->setEncryptedMeta('abc');

        $secureMessage->wipeEncryptedMetaFromMemory();
        $this->assertEmpty($secureMessage->getEncryptionKey());
    }

    public function testGetEncryptionKey(): void
    {
        $secureMessage = new SecureMessage();
        $secureMessage->setDatabaseKey('abc');
        $secureMessage->setStorageKey('def');
        $secureMessage->setVerificationCode('ghi');

        $this->assertSame('abcdefghi', $secureMessage->getEncryptionKey());
    }

    public function testSettersGetters(): void
    {
        $secureMessage = new SecureMessage();
        $this->assertSame('storageKey', $secureMessage->setStorageKey('storageKey')->getStorageKey());
        $this->assertSame('databaseKey', $secureMessage->setDatabaseKey('databaseKey')->getDatabaseKey());
        $this->assertSame('databaseKeystorageKeymetaKey', $secureMessage->setMetaKey('metaKey')->getMetaKey());
        $this->assertSame('id', $secureMessage->setId('id')->getId());
        $this->assertSame('encryptedContent', $secureMessage->setEncryptedContent('encryptedContent')->getEncryptedContent());
        $this->assertSame('encryptedMeta', $secureMessage->setEncryptedMeta('encryptedMeta')->getEncryptedMeta());
        $this->assertSame('content', $secureMessage->setContent('content')->getContent());
        $this->assertSame('verificationCode', $secureMessage->setVerificationCode('verificationCode')->getVerificationCode());
        $this->assertSame(['meta'], $secureMessage->setMeta(['meta'])->getMeta());
        $this->assertSame(1, $secureMessage->setHitPoints(1)->getHitPoints());
        $this->assertSame(1, $secureMessage->setExpiresAt(1)->getExpiresAt());
    }

    public function testFileMetaAccessors(): void
    {
        $secureMessage = new SecureMessage();

        $this->assertFalse($secureMessage->isFile());
        $this->assertNull($secureMessage->getFileName());
        $this->assertNull($secureMessage->getMimeType());
        $this->assertNull($secureMessage->getFileSize());

        $secureMessage->setFileName('report.pdf')->setMimeType('application/pdf')->setFileSize(1337);

        $this->assertTrue($secureMessage->isFile());
        $this->assertSame('report.pdf', $secureMessage->getFileName());
        $this->assertSame('application/pdf', $secureMessage->getMimeType());
        $this->assertSame(1337, $secureMessage->getFileSize());
    }

    public function testSetFileNameRejectsInvalidUtf8(): void
    {
        $secureMessage = new SecureMessage();

        $this->expectException(InvalidFileException::class);
        $secureMessage->setFileName("\xC3\x28invalid.bin");
    }

    public function testSetMimeTypeRejectsInvalidUtf8(): void
    {
        $secureMessage = new SecureMessage();

        $this->expectException(InvalidFileException::class);
        $secureMessage->setMimeType("application/\xC3\x28");
    }

    public function testSetMetaCastsFileSize(): void
    {
        $secureMessage = new SecureMessage();
        $secureMessage->setMeta(['hit_points' => '3', 'expires_at' => '10', 'file_size' => '2048', 'file_name' => 'a.txt']);

        $this->assertSame(2048, $secureMessage->getFileSize());
        $this->assertSame('a.txt', $secureMessage->getFileName());
        $this->assertSame(3, $secureMessage->getHitPoints());
    }

    public function testIsEncrypted(): void
    {
        $secureMessage = new SecureMessage();

        $this->assertFalse($secureMessage->isMetaEncrypted());
        $this->assertFalse($secureMessage->isContentEncrypted());

        $secureMessage->setEncryptedMeta('meta');
        $secureMessage->setEncryptedContent('data');

        $this->assertTrue($secureMessage->isMetaEncrypted());
        $this->assertTrue($secureMessage->isContentEncrypted());
    }
}
