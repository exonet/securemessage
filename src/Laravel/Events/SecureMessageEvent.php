<?php

declare(strict_types=1);

namespace Exonet\SecureMessage\Laravel\Events;

use Exonet\SecureMessage\SecureMessage;

class SecureMessageEvent
{
    /**
     * Create a new event instance.
     *
     * @param SecureMessage $secureMessage The secure message.
     */
    public function __construct(public readonly SecureMessage $secureMessage) {}
}
