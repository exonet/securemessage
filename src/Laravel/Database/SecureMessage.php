<?php

declare(strict_types=1);

namespace Exonet\SecureMessage\Laravel\Database;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string      $id         The secure message ID.
 * @property string      $meta       The encrypted meta data.
 * @property string      $content    The encrypted content.
 * @property string      $key        The encrypted database key.
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class SecureMessage extends Model
{
    /**
     * {@inheritdoc}
     */
    public $incrementing = false;

    /**
     * {@inheritdoc}
     */
    public $table = 'secure_messages';

    /**
     * {@inheritdoc}
     */
    protected $keyType = 'string';
}
