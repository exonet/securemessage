<?php

namespace Exonet\SecureMessage\Laravel\Providers;

use Exonet\SecureMessage\Laravel\Console\Housekeeping;
use Exonet\SecureMessage\Laravel\Factory as LaravelSecureMessageFactory;
use Exonet\SecureMessage\Laravel\SecureMessageFacade;
use Illuminate\Foundation\AliasLoader;
use Illuminate\Support\ServiceProvider;

class SecureMessageServiceProvider extends ServiceProvider
{
    /**
     * {@inheritdoc}
     */
    public function register() : void
    {
        // Load the migration and the config.
        $this->loadMigrationsFrom(__DIR__.'/../Database/Migrations');
        $this->mergeConfigFrom(__DIR__.'/../config/secure_messages.php', 'secure_messages');

        // Register the housekeeping command.
        $this->commands([Housekeeping::class]);

        // Create a container binding (used by the facade).
        $this->app->bind('secureMessage', function () {
            return $this->app->make(LaravelSecureMessageFactory::class);
        });

        // Register the facade.
        AliasLoader::getInstance()->alias('SecureMessage', SecureMessageFacade::class);
    }
}
