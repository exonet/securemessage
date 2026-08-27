<?php

declare(strict_types=1);

namespace Exonet\SecureMessage\Tests;

use Exonet\SecureMessage\Crypto;
use Exonet\SecureMessage\Exceptions\InvalidFileException;
use Exonet\SecureMessage\Exceptions\InvalidKeyLengthException;
use Exonet\SecureMessage\Factory;
use Exonet\SecureMessage\SecureMessage;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
class FactoryTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    public function testMake(): void
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

    public function testEncrypt(): void
    {
        $factory = (new Factory('metaKey___'))->make('Unit Test', 3, 1337);
        $secureMessageResult = new SecureMessage();

        $cryptoMock = \Mockery::mock(Crypto::class);
        $cryptoMock->shouldReceive('encrypt')->withArgs([\Mockery::on(function (SecureMessage $secureMessage) {
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

    public function testDecrypt(): void
    {
        $factory = (new Factory('metaKey___'))->make('Unit Test', 3, 1337);
        $secureMessageResult = new SecureMessage();
        $secureMessage = new SecureMessage();
        $secureMessage->setContent('Unit Test');

        $cryptoMock = \Mockery::mock(Crypto::class);
        $cryptoMock->shouldReceive('decrypt')->withArgs([\Mockery::on(function (SecureMessage $secureMessage) {
            $this->assertSame('Unit Test', $secureMessage->getContent());
            $this->assertNull($secureMessage->getMetaKey());

            return true;
        })])->andReturn($secureMessageResult);

        $factory->setCryptoInstance($cryptoMock);

        $this->assertSame($secureMessageResult, $factory->decrypt($secureMessage));
    }

    public function testDecryptMeta(): void
    {
        $factory = (new Factory('metaKey___'))->make('Unit Test', 3, 1337);
        $secureMessageResult = new SecureMessage();
        $secureMessage = new SecureMessage();
        $secureMessage->setContent('Unit Test');

        $cryptoMock = \Mockery::mock(Crypto::class);
        $cryptoMock->shouldReceive('decryptMeta')->withArgs([\Mockery::on(function (SecureMessage $secureMessage) {
            $this->assertSame('Unit Test', $secureMessage->getContent());
            $this->assertNull($secureMessage->getMetaKey());

            return true;
        })])->andReturn($secureMessageResult);

        $factory->setCryptoInstance($cryptoMock);

        $this->assertSame($secureMessageResult, $factory->decryptMeta($secureMessage));
    }

    public function testValidateEncryptionKey(): void
    {
        $factory = (new Factory('metaKey___'))->make('Unit Test', 3, 1337);
        $secureMessage = new SecureMessage();
        $secureMessage->setContent('Unit Test');

        $cryptoMock = \Mockery::mock(Crypto::class);
        $cryptoMock->shouldReceive('validateEncryptionKey')->withArgs([\Mockery::on(function (SecureMessage $secureMessage) {
            $this->assertSame('Unit Test', $secureMessage->getContent());
            $this->assertNull($secureMessage->getMetaKey());

            return true;
        })])->andReturnTrue();

        $factory->setCryptoInstance($cryptoMock);

        $this->assertTrue($factory->validateEncryptionKey($secureMessage));
    }

    public function testMakeFile(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'securemessage');
        file_put_contents($path, 'Unit Test file contents');

        try {
            $factory = new Factory();
            $result = $factory->makeFile($path, 1, 10);

            $this->assertNotSame($factory, $result);
            $this->assertSame('Unit Test file contents', $result->secureMessage->getContent());
            $this->assertTrue($result->secureMessage->isFile());
            $this->assertSame(basename($path), $result->secureMessage->getFileName());
            $this->assertSame('text/plain', $result->secureMessage->getMimeType());
            $this->assertSame(23, $result->secureMessage->getFileSize());
            $this->assertSame(1, $result->secureMessage->getHitPoints());
            $this->assertSame(10, $result->secureMessage->getExpiresAt());
        } finally {
            unlink($path);
        }
    }

    public function testMakeFileWithFileNameOverride(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'securemessage');
        file_put_contents($path, 'Unit Test file contents');

        try {
            $result = (new Factory())->makeFile($path, fileName: 'report.txt');

            $this->assertSame('report.txt', $result->secureMessage->getFileName());
        } finally {
            unlink($path);
        }
    }

    public function testMakeFileMissingPath(): void
    {
        $this->expectException(InvalidFileException::class);
        (new Factory())->makeFile(sys_get_temp_dir().'/does-not-exist.bin');
    }

    public function testMakeFileDirectoryPath(): void
    {
        $this->expectException(InvalidFileException::class);
        (new Factory())->makeFile(sys_get_temp_dir());
    }

    public function testSetMetaKey(): void
    {
        $factory = new Factory();

        $this->assertSame($factory, $factory->setMetaKey('metaKey___'));

        $this->expectException(InvalidKeyLengthException::class);
        $factory->setMetaKey('invalid_Key');
    }
}
