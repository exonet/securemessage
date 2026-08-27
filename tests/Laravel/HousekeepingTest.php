<?php

declare(strict_types=1);

namespace Exonet\SecureMessage\Tests\Laravel;

use Exonet\SecureMessage\Laravel\Console\Housekeeping;
use Exonet\SecureMessage\Laravel\Database\SecureMessage as SecureMessageModel;
use Exonet\SecureMessage\Laravel\Factory as SecureMessageFactory;
use Exonet\SecureMessage\Laravel\Providers\SecureMessageServiceProvider;
use Exonet\SecureMessage\SecureMessage;
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

        $command->handle($factoryMock, $modelMock);
    }

    protected function getPackageProviders($app): array
    {
        return [SecureMessageServiceProvider::class];
    }
}
