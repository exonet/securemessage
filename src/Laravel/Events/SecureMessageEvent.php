<?php

namespace Exonet\SecureMessage\Laravel\Events;

use Exonet\SecureMessage\SecureMessage;

class SecureMessageEvent
{
    /**
     * @var SecureMessage The secure message.
     */
    private $secureMessage;

    /**
     * Create a new event instance.
     *
     * @param SecureMessage $secureMessage The secure message.
     */
    public function __construct(SecureMessage $secureMessage)
    {
        $this->secureMessage = $secureMessage;
    }
}
