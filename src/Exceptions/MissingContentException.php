<?php

declare(strict_types=1);

namespace Exonet\SecureMessage\Exceptions;

/**
 * A stored part of the message (the storage key or the file blob) is gone. The verification code
 * was never checked, so this is not a wrong code.
 */
class MissingContentException extends DecryptException {}
