<?php

namespace Exonet\SecureMessage\tests;

use Exonet\SecureMessage\SecureMessage;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
class SecureMessageTest extends TestCase
{
    public function testWipeKeysFromMemory()
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

    public function testWipeContentFromMemory()
    {
        $secureMessage = new SecureMessage();
        $secureMessage->setContent('abc');

        $secureMessage->wipeContentFromMemory();
        $this->assertNull($secureMessage->getContent());
    }

    public function testWipeEncryptedContentFromMemory()
    {
        $secureMessage = new SecureMessage();
        $secureMessage->setEncryptedContent('abc');

        $secureMessage->wipeEncryptedContentFromMemory();
        $this->assertNull($secureMessage->getEncryptedContent());
    }

    public function testWipeEncryptedMetaFromMemory()
    {
        $secureMessage = new SecureMessage();
        $secureMessage->setEncryptedMeta('abc');

        $secureMessage->wipeEncryptedMetaFromMemory();
        $this->assertEmpty($secureMessage->getEncryptionKey());
    }

    public function testGetEncryptionKey()
    {
        $secureMessage = new SecureMessage();
        $secureMessage->setDatabaseKey('abc');
        $secureMessage->setStorageKey('def');
        $secureMessage->setVerificationCode('ghi');

        $this->assertSame('abcdefghi', $secureMessage->getEncryptionKey());
    }

    public function testSettersGetters()
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

    public function testIsEncrypted()
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
