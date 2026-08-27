<?php

declare(strict_types=1);

namespace Exonet\SecureMessage\Tests\Laravel;

use Carbon\Carbon;
use Exonet\SecureMessage\Exceptions\DecryptException;
use Exonet\SecureMessage\Exceptions\ExpiredException;
use Exonet\SecureMessage\Exceptions\HitPointLimitReachedException;
use Exonet\SecureMessage\Exceptions\InvalidFileException;
use Exonet\SecureMessage\Factory as SecureMessageFactory;
use Exonet\SecureMessage\Laravel\Database\SecureMessage as SecureMessageModel;
use Exonet\SecureMessage\Laravel\Events\DecryptionFailed;
use Exonet\SecureMessage\Laravel\Events\HitPointLimitReached;
use Exonet\SecureMessage\Laravel\Events\SecureMessageExpired;
use Exonet\SecureMessage\Laravel\Factory;
use Exonet\SecureMessage\Laravel\Providers\SecureMessageServiceProvider;
use Exonet\SecureMessage\SecureMessage;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Events\Dispatcher as Event;
use Illuminate\Contracts\Filesystem\Factory as Storage;
use Illuminate\Contracts\Filesystem\Filesystem;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;

/**
 * @internal
 */
class FactoryTest extends TestCase
{
    use MockeryPHPUnitIntegration;
    use RefreshDatabase;

    protected function tearDown(): void
    {
        Carbon::setTestNow();
        parent::tearDown();
    }

    public function testEncrypt(): void
    {
        Carbon::setTestNow(Carbon::create(2018, 4, 24, 9, 32, 33));

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $storageDiskMock = \Mockery::mock(Filesystem::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.expires_in'])->once()->andReturn(1);
        $configMock->shouldReceive('get')->withArgs(['secure_messages.hit_points'])->once()->andReturn(100);

        $createdSecureMessage = new SecureMessage();
        $createdSecureMessage->setId('secureMessageKey');

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();
        $secureMessageFactoryMock->shouldReceive('make')->withArgs(['Unit Test', 100, 1524648753])->once()->andReturnSelf();
        $secureMessageFactoryMock->shouldReceive('encrypt')->withNoArgs()->once()->andReturn($createdSecureMessage);

        $encrypterMock
            ->shouldReceive('encrypt')
            ->withArgs([\Mockery::any()])
            ->times(4)
            ->andReturn('encryptedKey', 'encryptedMeta', 'encryptedContent', 'encryptedDbKey');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturn($storageDiskMock);
        $storageDiskMock->shouldReceive('put')->withArgs(['secureMessageKey', 'encryptedKey'])->once();

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);
        $encryptedMessage = $factory->encrypt('Unit Test');

        $this->assertDatabaseHas('secure_messages', ['id' => $encryptedMessage->getId()]);
    }

    public function testDecryptMessage(): void
    {
        $this->insertSecureMessageRecord();

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $storageDiskMock = \Mockery::mock(Filesystem::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $decryptedSecureMessage = new SecureMessage();
        $decryptedSecureMessage->setContent('Decrypted content');

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');

        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedDatabaseKey'])->twice()->andReturn('databaseKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedStorageKey'])->twice()->andReturn('storageKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedMeta'])->twice()->andReturn('meta');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedContent'])->twice()->andReturn('content');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturn($storageDiskMock);
        $storageDiskMock->shouldReceive('exists')->withArgs(['unitTest'])->twice()->andReturnTrue();
        $storageDiskMock->shouldReceive('get')->withArgs(['unitTest'])->twice()->andReturn('encryptedStorageKey');

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();
        $secureMessageFactoryMock->shouldReceive('decrypt')->withArgs([\Mockery::on(function (SecureMessage $secureMessage) {
            $this->assertSame('unitTest', $secureMessage->getId());
            $this->assertSame('databaseKey', $secureMessage->getDatabaseKey());
            $this->assertSame('storageKey', $secureMessage->getStorageKey());
            $this->assertSame('1337', $secureMessage->getVerificationCode());
            $this->assertSame('meta', $secureMessage->getEncryptedMeta());
            $this->assertSame('content', $secureMessage->getEncryptedContent());

            return true;
        })])->twice()->andReturn($decryptedSecureMessage);

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);

        $this->assertSame($decryptedSecureMessage, $factory->decryptMessage('unitTest', '1337'));
        $this->assertSame('Decrypted content', $factory->decrypt('unitTest', '1337'));
    }

    public function testCheckVerificationCode(): void
    {
        $this->insertSecureMessageRecord();

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $storageDiskMock = \Mockery::mock(Filesystem::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');

        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedDatabaseKey'])->once()->andReturn('databaseKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedStorageKey'])->once()->andReturn('storageKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedMeta'])->once()->andReturn('meta');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedContent'])->once()->andReturn('content');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturn($storageDiskMock);
        $storageDiskMock->shouldReceive('exists')->withArgs(['unitTest'])->once()->andReturnTrue();
        $storageDiskMock->shouldReceive('get')->withArgs(['unitTest'])->once()->andReturn('encryptedStorageKey');

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();
        $secureMessageFactoryMock->shouldReceive('validateEncryptionKey')->withArgs([\Mockery::on(function (SecureMessage $secureMessage) {
            $this->assertSame('unitTest', $secureMessage->getId());
            $this->assertSame('databaseKey', $secureMessage->getDatabaseKey());
            $this->assertSame('storageKey', $secureMessage->getStorageKey());
            $this->assertSame('1337', $secureMessage->getVerificationCode());
            $this->assertSame('meta', $secureMessage->getEncryptedMeta());
            $this->assertSame('content', $secureMessage->getEncryptedContent());

            return true;
        })])->once()->andReturnTrue();

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);

        $this->assertTrue($factory->checkVerificationCode('unitTest', '1337'));
    }

    public function testDecryptMessageStorageKeyNotFound(): void
    {
        $this->insertSecureMessageRecord();

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $storageDiskMock = \Mockery::mock(Filesystem::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');

        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedDatabaseKey'])->once()->andReturn('databaseKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedStorageKey'])->never();
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedMeta'])->once()->andReturn('meta');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedContent'])->once()->andReturn('content');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturn($storageDiskMock);
        $storageDiskMock->shouldReceive('exists')->withArgs(['unitTest'])->once()->andReturnFalse();

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();

        $eventMock->shouldReceive('dispatch')->withArgs([\Mockery::on(function ($event) {
            // The event must not expose any key material to listeners, even though this failure path
            // throws without a secure message (so the DecryptException constructor never wiped it).
            $this->assertNull($event->secureMessage->getDatabaseKey());
            $this->assertNull($event->secureMessage->getStorageKey());
            $this->assertNull($event->secureMessage->getMetaKey());
            $this->assertNull($event->secureMessage->getVerificationCode());

            return $event::class === DecryptionFailed::class;
        })])->once();

        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage('Can not find key file.');

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);
        $factory->decryptMessage('unitTest', '1337');
    }

    public function testDecryptMessageHitpointLimitReached(): void
    {
        $this->insertSecureMessageRecord();

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $storageDiskMock = \Mockery::mock(Filesystem::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');

        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedDatabaseKey'])->once()->andReturn('databaseKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedStorageKey'])->once()->andReturn('storageKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedMeta'])->once()->andReturn('meta');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedContent'])->once()->andReturn('content');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturn($storageDiskMock);
        $storageDiskMock->shouldReceive('exists')->withArgs(['unitTest'])->once()->andReturnTrue();
        $storageDiskMock->shouldReceive('get')->withArgs(['unitTest'])->once()->andReturn('encryptedStorageKey');

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();
        $secureMessageFactoryMock->shouldReceive('decrypt')->withAnyArgs()->once()->andThrow(new HitPointLimitReachedException('The maximum number of hit points is reached.'));

        $eventMock->shouldReceive('dispatch')->withArgs([\Mockery::on(function ($event) {
            return $event::class === HitPointLimitReached::class;
        })])->once();

        $this->expectException(DecryptException::class);

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);
        $factory->decryptMessage('unitTest', '1337');
    }

    public function testDecryptMessageMessageExpired(): void
    {
        $this->insertSecureMessageRecord();

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $storageDiskMock = \Mockery::mock(Filesystem::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');

        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedDatabaseKey'])->once()->andReturn('databaseKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedStorageKey'])->once()->andReturn('storageKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedMeta'])->once()->andReturn('meta');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedContent'])->once()->andReturn('content');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturn($storageDiskMock);
        $storageDiskMock->shouldReceive('exists')->withArgs(['unitTest'])->once()->andReturnTrue();
        $storageDiskMock->shouldReceive('get')->withArgs(['unitTest'])->once()->andReturn('encryptedStorageKey');

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();
        $secureMessageFactoryMock->shouldReceive('decrypt')->withAnyArgs()->once()->andThrow(new ExpiredException('This secure message is expired.'));

        $eventMock->shouldReceive('dispatch')->withArgs([\Mockery::on(function ($event) {
            return $event::class === SecureMessageExpired::class;
        })])->once();

        $this->expectException(DecryptException::class);

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);
        $factory->decryptMessage('unitTest', '1337');
    }

    public function testDecryptMeta(): void
    {
        $this->insertSecureMessageRecord();

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $storageDiskMock = \Mockery::mock(Filesystem::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $decryptedSecureMessage = new SecureMessage();
        $decryptedSecureMessage->setContent('Decrypted content');

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');

        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedDatabaseKey'])->once()->andReturn('databaseKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedMeta'])->once()->andReturn('meta');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturn($storageDiskMock);
        $storageDiskMock->shouldReceive('exists')->withArgs(['unitTest'])->once()->andReturnTrue();
        $storageDiskMock->shouldReceive('get')->withArgs(['unitTest'])->once()->andReturn('encryptedStorageKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedStorageKey'])->once()->andReturn('storageKey');

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();
        $secureMessageFactoryMock->shouldReceive('decryptMeta')->withArgs([\Mockery::on(function (SecureMessage $secureMessage) {
            $this->assertSame('unitTest', $secureMessage->getId());
            $this->assertSame('meta', $secureMessage->getEncryptedMeta());

            return true;
        })])->once()->andReturn($decryptedSecureMessage);

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);

        $this->assertSame($decryptedSecureMessage, $factory->getMeta('unitTest'));
    }

    public function testDestroy(): void
    {
        $this->insertSecureMessageRecord();

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $storageDiskMock = \Mockery::mock(Filesystem::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturn($storageDiskMock);
        $storageDiskMock->shouldReceive('delete')->withArgs(['unitTest'])->once()->andReturnSelf();

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);
        $factory->destroy('unitTest');

        $this->assertDatabaseMissing('secure_messages', ['id' => 'unitTest']);
    }

    public function testEncryptFile(): void
    {
        Carbon::setTestNow(Carbon::create(2018, 4, 24, 9, 32, 33));

        $path = tempnam(sys_get_temp_dir(), 'securemessage');
        file_put_contents($path, 'Unit Test file contents');

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $storageDiskMock = \Mockery::mock(Filesystem::class);
        $filesDiskMock = \Mockery::mock(Filesystem::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.files_disk_name'])->once()->andReturn('secure_messages_files');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.max_file_size'])->once()->andReturn(10485760);
        $configMock->shouldReceive('get')->withArgs(['secure_messages.expires_in'])->once()->andReturn(1);
        $configMock->shouldReceive('get')->withArgs(['secure_messages.hit_points'])->once()->andReturn(100);

        $createdSecureMessage = new SecureMessage();
        $createdSecureMessage->setId('secureMessageKey');
        $createdSecureMessage->setEncryptedMeta('rawMeta');
        $createdSecureMessage->setEncryptedContent('rawContent');
        $createdSecureMessage->setDatabaseKey('rawDbKey');
        $createdSecureMessage->setStorageKey('rawStorageKey');

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();
        $secureMessageFactoryMock->shouldReceive('makeFile')->withArgs([$path, 100, 1524648753, null])->once()->andReturnSelf();
        $secureMessageFactoryMock->shouldReceive('encrypt')->withNoArgs()->once()->andReturn($createdSecureMessage);

        $encrypterMock
            ->shouldReceive('encrypt')
            ->withArgs([\Mockery::any()])
            ->times(4)
            ->andReturn('encryptedKey', 'encryptedBlob', 'encryptedMeta', 'encryptedDbKey');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturn($storageDiskMock);
        $storageMock->shouldReceive('disk')->withArgs(['secure_messages_files'])->once()->andReturn($filesDiskMock);
        $storageDiskMock->shouldReceive('put')->withArgs(['secureMessageKey', 'encryptedKey'])->once();
        $filesDiskMock->shouldReceive('put')->withArgs(['files/secureMessageKey', 'encryptedBlob'])->once();

        try {
            $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);
            $encryptedMessage = $factory->encryptFile($path);

            $this->assertDatabaseHas('secure_messages', ['id' => $encryptedMessage->getId(), 'content' => null]);
        } finally {
            unlink($path);
        }
    }

    public function testEncryptFileTooLarge(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'securemessage');
        file_put_contents($path, 'Unit Test file contents');

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $storageDiskMock = \Mockery::mock(Filesystem::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.max_file_size'])->once()->andReturn(10);

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturn($storageDiskMock);
        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();

        $this->expectException(InvalidFileException::class);

        try {
            $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);
            $factory->encryptFile($path);
        } finally {
            unlink($path);
        }
    }

    public function testDecryptFileMessage(): void
    {
        $this->insertSecureMessageRecord(null);

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $storageDiskMock = \Mockery::mock(Filesystem::class);
        $filesDiskMock = \Mockery::mock(Filesystem::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $decryptedSecureMessage = new SecureMessage();
        $decryptedSecureMessage->setContent('Decrypted file contents');

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.files_disk_name'])->once()->andReturn('secure_messages_files');

        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedDatabaseKey'])->once()->andReturn('databaseKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedStorageKey'])->once()->andReturn('storageKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedMeta'])->once()->andReturn('meta');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedBlob'])->once()->andReturn('content');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturn($storageDiskMock);
        $storageMock->shouldReceive('disk')->withArgs(['secure_messages_files'])->once()->andReturn($filesDiskMock);
        $storageDiskMock->shouldReceive('exists')->withArgs(['unitTest'])->once()->andReturnTrue();
        $storageDiskMock->shouldReceive('get')->withArgs(['unitTest'])->once()->andReturn('encryptedStorageKey');
        $filesDiskMock->shouldReceive('exists')->withArgs(['files/unitTest'])->once()->andReturnTrue();
        $filesDiskMock->shouldReceive('get')->withArgs(['files/unitTest'])->once()->andReturn('encryptedBlob');

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();
        $secureMessageFactoryMock->shouldReceive('decrypt')->withArgs([\Mockery::on(function (SecureMessage $secureMessage) {
            $this->assertSame('unitTest', $secureMessage->getId());
            $this->assertSame('databaseKey', $secureMessage->getDatabaseKey());
            $this->assertSame('storageKey', $secureMessage->getStorageKey());
            $this->assertSame('1337', $secureMessage->getVerificationCode());
            $this->assertSame('meta', $secureMessage->getEncryptedMeta());
            $this->assertSame('content', $secureMessage->getEncryptedContent());

            return true;
        })])->once()->andReturn($decryptedSecureMessage);

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);

        $this->assertSame($decryptedSecureMessage, $factory->decryptMessage('unitTest', '1337'));
    }

    public function testDecryptFileMessageBlobMissing(): void
    {
        $this->insertSecureMessageRecord(null);

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $storageDiskMock = \Mockery::mock(Filesystem::class);
        $filesDiskMock = \Mockery::mock(Filesystem::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.files_disk_name'])->once()->andReturn('secure_messages_files');

        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedDatabaseKey'])->once()->andReturn('databaseKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedMeta'])->once()->andReturn('meta');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturn($storageDiskMock);
        $storageMock->shouldReceive('disk')->withArgs(['secure_messages_files'])->once()->andReturn($filesDiskMock);
        $filesDiskMock->shouldReceive('exists')->withArgs(['files/unitTest'])->once()->andReturnFalse();

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();

        $eventMock->shouldReceive('dispatch')->withArgs([\Mockery::on(function ($event) {
            // The event must not expose any key material to listeners, even though this failure path
            // throws without a secure message (so the DecryptException constructor never wiped it).
            $this->assertNull($event->secureMessage->getDatabaseKey());
            $this->assertNull($event->secureMessage->getStorageKey());
            $this->assertNull($event->secureMessage->getMetaKey());
            $this->assertNull($event->secureMessage->getVerificationCode());

            return $event::class === DecryptionFailed::class;
        })])->once();

        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage('Can not find file blob.');

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);
        $factory->decryptMessage('unitTest', '1337');
    }

    public function testDecryptFileMessageHitpointLimitReached(): void
    {
        $this->insertSecureMessageRecord(null);

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $storageDiskMock = \Mockery::mock(Filesystem::class);
        $filesDiskMock = \Mockery::mock(Filesystem::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.files_disk_name'])->once()->andReturn('secure_messages_files');

        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedDatabaseKey'])->once()->andReturn('databaseKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedStorageKey'])->once()->andReturn('storageKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedMeta'])->once()->andReturn('meta');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedBlob'])->once()->andReturn('content');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturn($storageDiskMock);
        $storageMock->shouldReceive('disk')->withArgs(['secure_messages_files'])->once()->andReturn($filesDiskMock);
        $storageDiskMock->shouldReceive('exists')->withArgs(['unitTest'])->once()->andReturnTrue();
        $storageDiskMock->shouldReceive('get')->withArgs(['unitTest'])->once()->andReturn('encryptedStorageKey');
        $filesDiskMock->shouldReceive('exists')->withArgs(['files/unitTest'])->once()->andReturnTrue();
        $filesDiskMock->shouldReceive('get')->withArgs(['files/unitTest'])->once()->andReturn('encryptedBlob');

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();
        $secureMessageFactoryMock->shouldReceive('decrypt')->withAnyArgs()->once()->andThrow(new HitPointLimitReachedException('The maximum number of hit points is reached.'));

        $eventMock->shouldReceive('dispatch')->withArgs([\Mockery::on(function ($event) {
            return $event::class === HitPointLimitReached::class;
        })])->once();

        $this->expectException(DecryptException::class);

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);
        $factory->decryptMessage('unitTest', '1337');
    }

    public function testDestroyFileMessage(): void
    {
        $this->insertSecureMessageRecord(null);

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $storageDiskMock = \Mockery::mock(Filesystem::class);
        $filesDiskMock = \Mockery::mock(Filesystem::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.files_disk_name'])->once()->andReturn('secure_messages_files');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturn($storageDiskMock);
        $storageMock->shouldReceive('disk')->withArgs(['secure_messages_files'])->once()->andReturn($filesDiskMock);
        $storageDiskMock->shouldReceive('delete')->withArgs(['unitTest'])->once()->andReturnSelf();
        $filesDiskMock->shouldReceive('delete')->withArgs(['files/unitTest'])->once()->andReturnSelf();

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);
        $factory->destroy('unitTest');

        $this->assertDatabaseMissing('secure_messages', ['id' => 'unitTest']);
    }

    protected function getPackageProviders($app): array
    {
        return [SecureMessageServiceProvider::class];
    }

    /**
     * Insert a secure message record with all non-nullable columns filled. A null content marks the
     * record as a file message.
     */
    private function insertSecureMessageRecord(?string $content = 'encryptedContent'): void
    {
        SecureMessageModel::insert([
            'id' => 'unitTest',
            'key' => 'encryptedDatabaseKey',
            'meta' => 'encryptedMeta',
            'content' => $content,
            'created_at' => Carbon::now(),
        ]);
    }
}
