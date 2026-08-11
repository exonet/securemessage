<?php

declare(strict_types=1);

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
    | expire date and hit points). This string MUST be 10 characters long.
    |
    | PLEASE NOTE: if you change this key while there are non-expired secure
    | messages, those messages CAN NOT be decrypted!
    |
    */
    'meta_key' => env('SECURE_MESSAGE_META_KEY', 'ChangeThis'),

    /*
    |--------------------------------------------------------------------------
    | File Storage Disk
    |--------------------------------------------------------------------------
    |
    | Here you can specify which disk entry the package must use to store the
    | encrypted contents of file messages. You can define this disk in
    | 'config/filesystems.php'. Use a disk that is separate from the
    | 'storage_disk_name' disk (and ideally separate from the database host),
    | so that no single compromised store holds multiple parts of the
    | encryption key material. Only required when using file messages.
    |
    */
    'files_disk_name' => 'secure_messages_files',

    /*
    |--------------------------------------------------------------------------
    | Maximum File Size
    |--------------------------------------------------------------------------
    |
    | The maximum size (in bytes) of files that can be stored as a secure
    | message. Files are encrypted in memory and the stored blob is roughly
    | three times the original file size, so this limit keeps memory and
    | storage usage bounded.
    |
    */
    'max_file_size' => 10485760,

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
