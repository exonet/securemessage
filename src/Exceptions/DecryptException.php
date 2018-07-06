<?php

namespace Exonet\SecureMessage\Exceptions;

use Exonet\SecureMessage\Crypto;
use Exonet\SecureMessage\SecureMessage;

class DecryptException extends SecureMessageException
{
    /**
     * @var SecureMessage The secure message.
     */
    public $secureMessage;

    /**
     * DecryptException constructor.
     *
     * @param string        $exceptionMessage The exception message.
     * @param SecureMessage $secureMessage    The SecureMessage instance. Can have updated meta data.
     * @param Crypto|null   $crypto           The instance of the crypto utility to use.
     */
    public function __construct(string $exceptionMessage, ?SecureMessage $secureMessage = null, ?Crypto $crypto = null)
    {
        if ($secureMessage !== null) {
            // Use the given Crypto instance, or if null, create a new one.
            $crypto = $crypto ?? new Crypto();
            $this->secureMessage = $crypto->encrypt($secureMessage);
            $this->secureMessage->wipeKeysFromMemory();
        }

        parent::__construct($exceptionMessage);
    }
}
