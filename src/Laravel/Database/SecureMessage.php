<?php

namespace Exonet\SecureMessage\Laravel\Database;

use Illuminate\Database\Eloquent\Model;

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
    protected $keyType = 'char';
}
