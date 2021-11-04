<?php

namespace Exonet\SecureMessage\Laravel\Providers;

use Exonet\SecureMessage\Laravel\Console\Housekeeping;
use Exonet\SecureMessage\Laravel\Factory as LaravelSecureMessageFactory;
use Illuminate\Support\ServiceProvider;

class SecureMessageServiceProvider extends ServiceProvider
{
    /**
     * {@inheritdoc}
     */
    public function boot()
    {
        $this->publishes([
            __DIR__.'/../config/secure_messages.php' => config_path('secure_messages.php'),
        ], 'config');
    }

    /**
     * {@inheritdoc}
     */
    public function register(): void
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
    }
}
