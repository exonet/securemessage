<?php

declare(strict_types=1);

namespace Exonet\SecureMessage\Laravel;

use Illuminate\Support\Facades\Facade;

class SecureMessageFacade extends Facade
{
    /**
     * {@inheritdoc}
     */
    protected static function getFacadeAccessor(): string
    {
        return 'secureMessage';
    }
}
