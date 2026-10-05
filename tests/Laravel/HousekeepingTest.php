<?php

declare(strict_types=1);

namespace Exonet\SecureMessage\Tests\Laravel;

use Exonet\SecureMessage\Exceptions\DecryptException;
use Exonet\SecureMessage\Exceptions\MissingContentException;
use Exonet\SecureMessage\Laravel\Console\Housekeeping;
use Exonet\SecureMessage\Laravel\Database\SecureMessage as SecureMessageModel;
use Exonet\SecureMessage\Laravel\Factory as SecureMessageFactory;
use Exonet\SecureMessage\Laravel\Providers\SecureMessageServiceProvider;
use Exonet\SecureMessage\SecureMessage;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;

/**
 * @internal
 */
class HousekeepingTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    public function testHandle(): void
    {
        $modelMock = \Mockery::mock(SecureMessageModel::class);
        $factoryMock = \Mockery::mock(SecureMessageFactory::class);

        $okSecureMessage = (new SecureMessage())->setId('abc')->setExpiresAt(time() + 10)->setHitPoints(3);
        $expiredSecureMessage = (new SecureMessage())->setId('abc')->setExpiresAt(time() - 10)->setHitPoints(3);
        $noHitPointsSecureMessage = (new SecureMessage())->setId('abc')->setExpiresAt(time() + 10)->setHitPoints(0);

        $modelMock->shouldReceive('pluck')->withArgs(['id'])->once()->andReturn(collect(['abc', 'def', 'xyz']));

        $factoryMock->shouldReceive('getMeta')->withArgs(['abc'])->once()->andReturn($okSecureMessage);
        $factoryMock->shouldReceive('getMeta')->withArgs(['def'])->once()->andReturn($expiredSecureMessage);
        $factoryMock->shouldReceive('getMeta')->withArgs(['xyz'])->once()->andReturn($noHitPointsSecureMessage);

        $factoryMock->shouldReceive('destroy')->withArgs(['abc'])->never();
        $factoryMock->shouldReceive('destroy')->withArgs(['def'])->once();
        $factoryMock->shouldReceive('destroy')->withArgs(['xyz'])->once();

        $command = \Mockery::mock(Housekeeping::class.'[getOutput,info]')->makePartial();
        $command->shouldReceive('getOutput->isVerbose')->times(2)->andReturnTrue();
        $command->shouldReceive('info')->withArgs(['Destroyed secure message [<comment>abc</comment>]'])->never();
        $command->shouldReceive('info')->withArgs(['Destroyed secure message [<comment>def</comment>]'])->once();
        $command->shouldReceive('info')->withArgs(['Destroyed secure message [<comment>xyz</comment>]'])->once();

        $this->assertSame(Housekeeping::SUCCESS, $command->handle($factoryMock, $modelMock));
    }

    public function testHandleSkipsUnreadableMessages(): void
    {
        $modelMock = \Mockery::mock(SecureMessageModel::class);
        $factoryMock = \Mockery::mock(SecureMessageFactory::class);

        $expiredSecureMessage = (new SecureMessage())->setId('xyz')->setExpiresAt(time() - 10)->setHitPoints(3);

        $modelMock->shouldReceive('pluck')->withArgs(['id'])->once()->andReturn(collect(['abc', 'def', 'xyz']));

        $factoryMock->shouldReceive('getMeta')->withArgs(['abc'])->once()->andThrow(new MissingContentException('Can not find key file.'));
        $factoryMock->shouldReceive('getMeta')->withArgs(['def'])->once()->andThrow(new DecryptException('Unable to or failed to decrypt the meta data.'));
        $factoryMock->shouldReceive('getMeta')->withArgs(['xyz'])->once()->andReturn($expiredSecureMessage);

        $factoryMock->shouldReceive('destroy')->withArgs(['abc'])->never();
        $factoryMock->shouldReceive('destroy')->withArgs(['def'])->never();
        $factoryMock->shouldReceive('destroy')->withArgs(['xyz'])->once();

        $command = \Mockery::mock(Housekeeping::class.'[getOutput,info,warn,option]')->makePartial();
        $command->shouldReceive('option')->withArgs(['destroy-missing'])->once()->andReturnFalse();
        $command->shouldReceive('getOutput->isVerbose')->once()->andReturnFalse();
        $command->shouldReceive('warn')->withArgs(['Skipped secure message [abc]: Can not find key file.'])->once();
        $command->shouldReceive('warn')->withArgs(['Skipped secure message [def]: Unable to or failed to decrypt the meta data.'])->once();

        $this->assertSame(Housekeeping::FAILURE, $command->handle($factoryMock, $modelMock));
    }

    public function testHandleIgnoresMessagesDestroyedDuringTheRun(): void
    {
        $modelMock = \Mockery::mock(SecureMessageModel::class);
        $factoryMock = \Mockery::mock(SecureMessageFactory::class);

        $expiredSecureMessage = (new SecureMessage())->setId('def')->setExpiresAt(time() - 10)->setHitPoints(3);

        $modelMock->shouldReceive('pluck')->withArgs(['id'])->once()->andReturn(collect(['abc', 'def']));

        $factoryMock->shouldReceive('getMeta')->withArgs(['abc'])->once()->andThrow(new ModelNotFoundException());
        $factoryMock->shouldReceive('getMeta')->withArgs(['def'])->once()->andReturn($expiredSecureMessage);

        $factoryMock->shouldReceive('destroy')->withArgs(['abc'])->never();
        $factoryMock->shouldReceive('destroy')->withArgs(['def'])->once();

        $command = \Mockery::mock(Housekeeping::class.'[getOutput,info,warn,option]')->makePartial();
        $command->shouldReceive('option')->never();
        $command->shouldReceive('getOutput->isVerbose')->once()->andReturnFalse();
        $command->shouldReceive('warn')->never();

        $this->assertSame(Housekeeping::SUCCESS, $command->handle($factoryMock, $modelMock));
    }

    public function testHandleDestroysMissingKeyFileWithOption(): void
    {
        $modelMock = \Mockery::mock(SecureMessageModel::class);
        $factoryMock = \Mockery::mock(SecureMessageFactory::class);

        $modelMock->shouldReceive('pluck')->withArgs(['id'])->once()->andReturn(collect(['abc']));

        $factoryMock->shouldReceive('getMeta')->withArgs(['abc'])->once()->andThrow(new MissingContentException('Can not find key file.'));
        $factoryMock->shouldReceive('destroy')->withArgs(['abc'])->once();

        $command = \Mockery::mock(Housekeeping::class.'[getOutput,info,warn,option]')->makePartial();
        $command->shouldReceive('option')->withArgs(['destroy-missing'])->once()->andReturnTrue();
        $command->shouldReceive('getOutput->isVerbose')->once()->andReturnTrue();
        $command->shouldReceive('info')->withArgs(['Destroyed secure message [<comment>abc</comment>]'])->once();
        $command->shouldReceive('warn')->never();

        $this->assertSame(Housekeeping::SUCCESS, $command->handle($factoryMock, $modelMock));
    }

    protected function getPackageProviders($app): array
    {
        return [SecureMessageServiceProvider::class];
    }
}
