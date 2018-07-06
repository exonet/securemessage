<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Filesystem Storage Disks
    |--------------------------------------------------------------------------
    |
    | Here you can specify which disk entry the package must use to store the
    | 'storage key'. You can define this in 'config/filesystems.php'.
    |
    */
    'storage_disk_name' => 'secure_messages',

    /*
    |--------------------------------------------------------------------------
    | Meta data encryption key.
    |--------------------------------------------------------------------------
    |
    | This key is being used to encrypt the meta data of a secure message (the
    | expire date and hit points). This string MUST be 32 characters long.
    |
    | PLEASE NOTE: if you change this key while there are non-expired secure
    | messages, those messages CAN NOT be decrypted!
    |
    */
    'meta_key' => env('SECURE_MESSAGE_META_KEY', 'ChangeThis'),

    /*
    |--------------------------------------------------------------------------
    | Hit Points
    |--------------------------------------------------------------------------
    |
    | Here you can specify how many times a wrong verification code can be
    | entered.
    |
    */
    'hit_points' => 3,

    /*
    |--------------------------------------------------------------------------
    | Default expire date
    |--------------------------------------------------------------------------
    |
    | Here you can specify after how many days a message will expire, if no
    | expire date is specified.
    |
    */
    'expires_in' => 10,
];
