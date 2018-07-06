<?php

namespace Exonet\SecureMessage\Laravel\Database;

use Illuminate\Database\Eloquent\Model;

class SecureMessage extends Model
{
    /**
     * {@inheritdoc}
     */
    protected $keyType = 'char';

    /**
     * {@inheritdoc}
     */
    public $incrementing = false;

    /**
     * {@inheritdoc}
     */
    public $table = 'secure_messages';
}
