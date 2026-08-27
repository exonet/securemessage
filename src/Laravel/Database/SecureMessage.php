<?php

declare(strict_types=1);

namespace Exonet\SecureMessage\Laravel\Database;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string      $id         The secure message ID.
 * @property string      $meta       The encrypted meta data.
 * @property string|null $content    The encrypted content. Null for file messages: their encrypted
 *                                   contents are stored on the configured files disk.
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
