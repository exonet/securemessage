<?php

declare(strict_types=1);

namespace Exonet\SecureMessage\Laravel\Console;

use Exonet\SecureMessage\Exceptions\DecryptException;
use Exonet\SecureMessage\Exceptions\MissingContentException;
use Exonet\SecureMessage\Laravel\Database\SecureMessage as SecureMessageModel;
use Exonet\SecureMessage\Laravel\Factory as SecureMessageFactory;
use Illuminate\Console\Command;
use Illuminate\Contracts\Encryption\DecryptException as LaravelDecryptException;
use Illuminate\Database\Eloquent\ModelNotFoundException;

class Housekeeping extends Command
{
    /**
     * {@inheritdoc}
     */
    protected $signature = 'secure_message:housekeeping
        {--destroy-missing : Also destroy the secure messages whose storage key file is missing}';

    /**
     * {@inheritdoc}
     */
    protected $description = 'Destroy all secure messages that are expired or have no hit points left.';

    /**
     * Run the housekeeping utility. All secure messages that are expired or have no hit points left are destroyed.
     * A secure message whose meta data can not be read is skipped, so one broken message does not stop the run.
     * One without its storage key file is only destroyed with --destroy-missing, because a misconfigured storage
     * disk makes every key file look missing.
     *
     * @param SecureMessageFactory $secureMessageFactory The Laravel secure message factory.
     * @param SecureMessageModel   $secureMessageModel   The database model.
     *
     * @return int The exit code: a failure when at least one secure message was skipped.
     */
    public function handle(SecureMessageFactory $secureMessageFactory, SecureMessageModel $secureMessageModel): int
    {
        $skipped = 0;

        $secureMessageModel
            ->pluck('id')
            ->each(function (string $secureMessageId) use ($secureMessageFactory, &$skipped) {
                try {
                    $meta = $secureMessageFactory->getMeta($secureMessageId);
                } catch (ModelNotFoundException) {
                    // Destroyed since the IDs were plucked, so there is nothing left to clean up.
                    return;
                } catch (DecryptException|LaravelDecryptException $exception) {
                    if ($exception instanceof MissingContentException && $this->option('destroy-missing')) {
                        $this->destroy($secureMessageFactory, $secureMessageId);

                        return;
                    }

                    $this->warn(sprintf('Skipped secure message [%s]: %s', $secureMessageId, $exception->getMessage()));
                    ++$skipped;

                    return;
                }

                $meta->wipeKeysFromMemory();

                // If there are no more hit points left, or the message is expired, destroy it.
                if ($meta->getHitPoints() <= 0 || $meta->getExpiresAt() < time()) {
                    $this->destroy($secureMessageFactory, $secureMessageId);
                }
            });

        return $skipped === 0 ? self::SUCCESS : self::FAILURE;
    }

    /**
     * @param SecureMessageFactory $secureMessageFactory The Laravel secure message factory.
     * @param string               $secureMessageId      The secure message ID.
     */
    private function destroy(SecureMessageFactory $secureMessageFactory, string $secureMessageId): void
    {
        $secureMessageFactory->destroy($secureMessageId);

        if ($this->getOutput()->isVerbose()) {
            $this->info(sprintf('Destroyed secure message [<comment>%s</comment>]', $secureMessageId));
        }
    }
}
