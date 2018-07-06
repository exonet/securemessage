<?php

namespace Exonet\SecureMessage\Laravel\tests;

use Exonet\SecureMessage\Laravel\Console\Housekeeping;
use Exonet\SecureMessage\Laravel\Database\SecureMessage as SecureMessageModel;
use Exonet\SecureMessage\Laravel\Factory as SecureMessageFactory;
use Exonet\SecureMessage\SecureMessage;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Testing\TestCase;
use Mockery;

class HousekeepingTest extends TestCase
{
    public function createApplication()
    {
        $app = require __DIR__.'/../../../../bootstrap/app.php';
        $app->make(Kernel::class)->bootstrap();

        return $app;
    }

    public function test_Handle()
    {
        $modelMock = Mockery::mock(SecureMessageModel::class);
        $factoryMock = Mockery::mock(SecureMessageFactory::class);

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

        $command = Mockery::mock(Housekeeping::class.'[getOutput,info]')->makePartial();
        $command->shouldReceive('getOutput->isVerbose')->times(2)->andReturnTrue();
        $command->shouldReceive('info')->withArgs(['Destroyed secure message [<comment>abc</comment>]'])->never();
        $command->shouldReceive('info')->withArgs(['Destroyed secure message [<comment>def</comment>]'])->once();
        $command->shouldReceive('info')->withArgs(['Destroyed secure message [<comment>xyz</comment>]'])->once();

        $command->handle($factoryMock, $modelMock);
    }
}
