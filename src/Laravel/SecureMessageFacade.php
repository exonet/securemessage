<?php

namespace Exonet\SecureMessage\Laravel;

use Illuminate\Support\Facades\Facade;

class SecureMessageFacade extends Facade
{
    /**
     * {@inheritdoc}
     */
    protected static function getFacadeAccessor()
    {
        return 'secureMessage';
    }
}
