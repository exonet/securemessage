<?php

namespace Exonet\SecureMessage\Laravel\Console;

use Exonet\SecureMessage\Laravel\Database\SecureMessage as SecureMessageModel;
use Exonet\SecureMessage\Laravel\Factory as SecureMessageFactory;
use Illuminate\Console\Command;

class Housekeeping extends Command
{
    /**
     * {@inheritdoc}
     */
    protected $signature = 'secure_message:housekeeping';

    /**
     * {@inheritdoc}
     */
    protected $description = 'Destroy all secure messages that are expired or have no hit points left.';

    /**
     * Run the housekeeping utility. All secure messages that are expired or have no hit points left are destroyed.
     *
     * @param SecureMessageFactory $secureMessageFactory The Laravel secure message factory.
     * @param SecureMessageModel   $secureMessageModel   The database model.
     */
    public function handle(SecureMessageFactory $secureMessageFactory, SecureMessageModel $secureMessageModel): void
    {
        $secureMessageModel
            ->pluck('id')
            ->each(function (string $secureMessageId) use ($secureMessageFactory) {
                $meta = $secureMessageFactory->getMeta($secureMessageId);
                $meta->wipeKeysFromMemory();

                // If there are no more hit points left, or the message is expired, destroy it.
                if ($meta->getHitPoints() <= 0 || $meta->getExpiresAt() < time()) {
                    $secureMessageFactory->destroy($secureMessageId);

                    // Output info if requested.
                    if ($this->getOutput()->isVerbose()) {
                        $this->info(sprintf('Destroyed secure message [<comment>%s</comment>]', $secureMessageId));
                    }
                }
            });
    }
}
