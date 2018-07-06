<?php

namespace Exonet\SecureMessage\tests;

use Exonet\SecureMessage\Crypto;
use Exonet\SecureMessage\Exceptions\InvalidKeyLengthException;
use Exonet\SecureMessage\Factory;
use Exonet\SecureMessage\SecureMessage;
use Mockery;
use PHPUnit\Framework\TestCase;

class FactoryTest extends TestCase
{
    public function test_Make()
    {
        $factory = new Factory();

        $resultSimple = $factory->make('Unit Test');
        $resultAll = $factory->make('Unit Test 2', 1, 10);

        // Assert that a _new_ instance of the factory is returned.
        $this->assertNotSame($factory, $resultSimple);
        $this->assertNotNull($resultSimple->secureMessage->getId());
        $this->assertSame('Unit Test', $resultSimple->secureMessage->getContent());
        $this->assertSame(3, $resultSimple->secureMessage->getHitPoints());
        $this->assertSame(time() + 86400, $resultSimple->secureMessage->getExpiresAt());

        // Assert that a _new_ instance of the factory is returned.
        $this->assertNotSame($factory, $resultSimple);
        $this->assertNotSame($resultSimple, $resultAll);
        $this->assertNotNull($resultAll->secureMessage->getId());
        $this->assertSame('Unit Test 2', $resultAll->secureMessage->getContent());
        $this->assertSame(1, $resultAll->secureMessage->getHitPoints());
        $this->assertSame(10, $resultAll->secureMessage->getExpiresAt());
    }

    public function test_Encrypt()
    {
        $factory = (new Factory('metaKey___'))->make('Unit Test', 3, 1337);
        $secureMessageResult = new SecureMessage();

        $cryptoMock = Mockery::mock(Crypto::class);
        $cryptoMock->shouldReceive('encrypt')->withArgs([Mockery::on(function (SecureMessage $secureMessage) {
            $this->assertSame('Unit Test', $secureMessage->getContent());
            $this->assertSame(3, $secureMessage->getHitPoints());
            $this->assertSame(1337, $secureMessage->getExpiresAt());
            $this->assertSame(32, strlen($secureMessage->getEncryptionKey()));
            $this->assertSame(
                $secureMessage->getDatabaseKey().$secureMessage->getStorageKey().'metaKey___',
                $secureMessage->getMetaKey()
            );

            return true;
        })])->andReturn($secureMessageResult);

        $factory->setCryptoInstance($cryptoMock);

        $this->assertSame($secureMessageResult, $factory->encrypt());
    }

    public function test_Decrypt()
    {
        $factory = (new Factory('metaKey___'))->make('Unit Test', 3, 1337);
        $secureMessageResult = new SecureMessage();
        $secureMessage = new SecureMessage();
        $secureMessage->setContent('Unit Test');

        $cryptoMock = Mockery::mock(Crypto::class);
        $cryptoMock->shouldReceive('decrypt')->withArgs([Mockery::on(function (SecureMessage $secureMessage) {
            $this->assertSame('Unit Test', $secureMessage->getContent());
            $this->assertNull($secureMessage->getMetaKey());

            return true;
        })])->andReturn($secureMessageResult);

        $factory->setCryptoInstance($cryptoMock);

        $this->assertSame($secureMessageResult, $factory->decrypt($secureMessage));
    }

    public function test_DecryptMeta()
    {
        $factory = (new Factory('metaKey___'))->make('Unit Test', 3, 1337);
        $secureMessageResult = new SecureMessage();
        $secureMessage = new SecureMessage();
        $secureMessage->setContent('Unit Test');

        $cryptoMock = Mockery::mock(Crypto::class);
        $cryptoMock->shouldReceive('decryptMeta')->withArgs([Mockery::on(function (SecureMessage $secureMessage) {
            $this->assertSame('Unit Test', $secureMessage->getContent());
            $this->assertNull($secureMessage->getMetaKey());

            return true;
        })])->andReturn($secureMessageResult);

        $factory->setCryptoInstance($cryptoMock);

        $this->assertSame($secureMessageResult, $factory->decryptMeta($secureMessage));
    }

    public function test_ValidateEncryptionKey()
    {
        $factory = (new Factory('metaKey___'))->make('Unit Test', 3, 1337);
        $secureMessage = new SecureMessage();
        $secureMessage->setContent('Unit Test');

        $cryptoMock = Mockery::mock(Crypto::class);
        $cryptoMock->shouldReceive('validateEncryptionKey')->withArgs([Mockery::on(function (SecureMessage $secureMessage) {
            $this->assertSame('Unit Test', $secureMessage->getContent());
            $this->assertNull($secureMessage->getMetaKey());

            return true;
        })])->andReturnTrue();

        $factory->setCryptoInstance($cryptoMock);

        $this->assertTrue($factory->validateEncryptionKey($secureMessage));
    }

    public function test_SetMetaKey()
    {
        $factory = new Factory();

        $this->assertSame($factory, $factory->setMetaKey('metaKey___'));

        $this->expectException(InvalidKeyLengthException::class);
        $factory->setMetaKey('invalid_Key');
    }
}
