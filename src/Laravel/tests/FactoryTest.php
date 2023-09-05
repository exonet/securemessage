<?php

namespace Exonet\SecureMessage\Laravel\tests;

use Carbon\Carbon;
use Exonet\SecureMessage\Exceptions\DecryptException;
use Exonet\SecureMessage\Exceptions\ExpiredException;
use Exonet\SecureMessage\Exceptions\HitPointLimitReachedException;
use Exonet\SecureMessage\Factory as SecureMessageFactory;
use Exonet\SecureMessage\Laravel\Database\SecureMessage as SecureMessageModel;
use Exonet\SecureMessage\Laravel\Events\DecryptionFailed;
use Exonet\SecureMessage\Laravel\Events\HitPointLimitReached;
use Exonet\SecureMessage\Laravel\Events\SecureMessageExpired;
use Exonet\SecureMessage\Laravel\Factory;
use Exonet\SecureMessage\SecureMessage;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Events\Dispatcher as Event;
use Illuminate\Contracts\Filesystem\Factory as Storage;
use Illuminate\Foundation\Testing\TestCase;

/**
 * @internal
 */
class FactoryTest extends TestCase
{
    protected function setUp()
    {
        parent::setUp();
        $this->app->make('db')->beginTransaction();
    }

    protected function tearDown()
    {
        $this->app->make('db')->rollBack();
        parent::tearDown();
    }

    public function createApplication()
    {
        $app = require __DIR__.'/../../../../bootstrap/app.php';
        $app->make(Kernel::class)->bootstrap();

        return $app;
    }

    public function testEncrypt()
    {
        Carbon::setTestNow(Carbon::create(2018, 4, 24, 9, 32, 33));

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
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

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturnSelf();
        $storageMock->shouldReceive('put')->withArgs(['secureMessageKey', 'encryptedKey'])->once();

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);
        $encryptedMessage = $factory->encrypt('Unit Test');

        $this->assertDatabaseHas('secure_messages', ['id' => $encryptedMessage->getId()]);
    }

    public function testDecryptMessage()
    {
        SecureMessageModel::insert([
            'id' => 'unitTest',
            'key' => 'encryptedDatabaseKey',
            'meta' => 'encryptedMeta',
            'content' => 'encryptedContent',
        ]);

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
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

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturnSelf();
        $storageMock->shouldReceive('exists')->withArgs(['unitTest'])->twice()->andReturnTrue();
        $storageMock->shouldReceive('get')->withArgs(['unitTest'])->twice()->andReturn('encryptedStorageKey');

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

    public function testCheckVerificationCode()
    {
        SecureMessageModel::insert([
            'id' => 'unitTest',
            'key' => 'encryptedDatabaseKey',
            'meta' => 'encryptedMeta',
            'content' => 'encryptedContent',
        ]);

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $decryptedSecureMessage = new SecureMessage();
        $decryptedSecureMessage->setContent('Decrypted content');

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');

        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedDatabaseKey'])->once()->andReturn('databaseKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedStorageKey'])->once()->andReturn('storageKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedMeta'])->once()->andReturn('meta');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedContent'])->once()->andReturn('content');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturnSelf();
        $storageMock->shouldReceive('exists')->withArgs(['unitTest'])->once()->andReturnTrue();
        $storageMock->shouldReceive('get')->withArgs(['unitTest'])->once()->andReturn('encryptedStorageKey');

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

    public function testDecryptMessageStorageKeyNotFound()
    {
        SecureMessageModel::insert([
            'id' => 'unitTest',
            'key' => 'encryptedDatabaseKey',
            'meta' => 'encryptedMeta',
            'content' => 'encryptedContent',
        ]);

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $decryptedSecureMessage = new SecureMessage();
        $decryptedSecureMessage->setContent('Decrypted content');

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');

        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedDatabaseKey'])->once()->andReturn('databaseKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedStorageKey'])->never();
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedMeta'])->once()->andReturn('meta');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedContent'])->once()->andReturn('content');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturnSelf();
        $storageMock->shouldReceive('exists')->withArgs(['unitTest'])->once()->andReturnFalse();

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();

        $eventMock->shouldReceive('dispatch')->withArgs([\Mockery::on(function ($event) {
            return get_class($event) === DecryptionFailed::class;
        })])->once();

        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage('Can not find key file.');

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);
        $factory->decryptMessage('unitTest', '1337');
    }

    public function testDecryptMessageHitpointLimitReached()
    {
        SecureMessageModel::insert([
            'id' => 'unitTest',
            'key' => 'encryptedDatabaseKey',
            'meta' => 'encryptedMeta',
            'content' => 'encryptedContent',
        ]);

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $decryptedSecureMessage = new SecureMessage();
        $decryptedSecureMessage->setContent('Decrypted content');

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');

        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedDatabaseKey'])->once()->andReturn('databaseKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedStorageKey'])->once()->andReturn('storageKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedMeta'])->once()->andReturn('meta');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedContent'])->once()->andReturn('content');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturnSelf();
        $storageMock->shouldReceive('exists')->withArgs(['unitTest'])->once()->andReturnTrue();
        $storageMock->shouldReceive('get')->withArgs(['unitTest'])->once()->andReturn('encryptedStorageKey');

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();
        $secureMessageFactoryMock->shouldReceive('decrypt')->withAnyArgs()->once()->andThrow(new HitPointLimitReachedException('The maximum number of hit points is reached.'));

        $eventMock->shouldReceive('dispatch')->withArgs([\Mockery::on(function ($event) {
            return get_class($event) === HitPointLimitReached::class;
        })])->once();

        $this->expectException(DecryptException::class);

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);
        $factory->decryptMessage('unitTest', '1337');
    }

    public function testDecryptMessageMessageExpired()
    {
        SecureMessageModel::insert([
            'id' => 'unitTest',
            'key' => 'encryptedDatabaseKey',
            'meta' => 'encryptedMeta',
            'content' => 'encryptedContent',
        ]);

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $decryptedSecureMessage = new SecureMessage();
        $decryptedSecureMessage->setContent('Decrypted content');

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');

        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedDatabaseKey'])->once()->andReturn('databaseKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedStorageKey'])->once()->andReturn('storageKey');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedMeta'])->once()->andReturn('meta');
        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedContent'])->once()->andReturn('content');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturnSelf();
        $storageMock->shouldReceive('exists')->withArgs(['unitTest'])->once()->andReturnTrue();
        $storageMock->shouldReceive('get')->withArgs(['unitTest'])->once()->andReturn('encryptedStorageKey');

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();
        $secureMessageFactoryMock->shouldReceive('decrypt')->withAnyArgs()->once()->andThrow(new ExpiredException('This secure message is expired.'));

        $eventMock->shouldReceive('dispatch')->withArgs([\Mockery::on(function ($event) {
            return get_class($event) === SecureMessageExpired::class;
        })])->once();

        $this->expectException(DecryptException::class);

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);
        $factory->decryptMessage('unitTest', '1337');
    }

    public function testDecryptMeta()
    {
        SecureMessageModel::insert([
            'id' => 'unitTest',
            'key' => 'encryptedDatabaseKey',
            'meta' => 'encryptedMeta',
            'content' => 'encryptedContent',
        ]);

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $decryptedSecureMessage = new SecureMessage();
        $decryptedSecureMessage->setContent('Decrypted content');

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');

        $encrypterMock->shouldReceive('decrypt')->withArgs(['encryptedMeta'])->once()->andReturn('meta');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturnSelf();

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();
        $secureMessageFactoryMock->shouldReceive('decryptMeta')->withArgs([\Mockery::on(function (SecureMessage $secureMessage) {
            $this->assertSame('unitTest', $secureMessage->getId());
            $this->assertSame('meta', $secureMessage->getEncryptedMeta());

            return true;
        })])->once()->andReturn($decryptedSecureMessage);

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);

        $this->assertSame($decryptedSecureMessage, $factory->getMeta('unitTest'));
    }

    public function testDestroy()
    {
        SecureMessageModel::insert(['id' => 'unitTest']);

        $secureMessageFactoryMock = \Mockery::mock(SecureMessageFactory::class);
        $storageMock = \Mockery::mock(Storage::class);
        $encrypterMock = \Mockery::mock(Encrypter::class);
        $configMock = \Mockery::mock(Config::class);
        $eventMock = \Mockery::mock(Event::class);

        $decryptedSecureMessage = new SecureMessage();
        $decryptedSecureMessage->setContent('Decrypted content');

        $configMock->shouldReceive('get')->withArgs(['secure_messages.meta_key'])->once()->andReturn('metaKey');
        $configMock->shouldReceive('get')->withArgs(['secure_messages.storage_disk_name'])->once()->andReturn('secure_messages');

        $storageMock->shouldReceive('disk')->withArgs(['secure_messages'])->once()->andReturnSelf();
        $storageMock->shouldReceive('delete')->withArgs(['unitTest'])->once()->andReturnSelf();

        $secureMessageFactoryMock->shouldReceive('setMetaKey')->withArgs(['metaKey'])->once()->andReturnSelf();

        $factory = new Factory($secureMessageFactoryMock, $storageMock, $encrypterMock, $configMock, $eventMock);
        $factory->destroy('unitTest');

        $this->assertDatabaseMissing('secure_messages', ['id' => 'unitTest']);
    }
}
