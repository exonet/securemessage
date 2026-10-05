<?php

declare(strict_types=1);

namespace Exonet\SecureMessage\Laravel;

use Carbon\Carbon;
use Exonet\SecureMessage\Exceptions\DecryptException;
use Exonet\SecureMessage\Exceptions\ExpiredException;
use Exonet\SecureMessage\Exceptions\HitPointLimitReachedException;
use Exonet\SecureMessage\Exceptions\InvalidFileException;
use Exonet\SecureMessage\Exceptions\InvalidKeyLengthException;
use Exonet\SecureMessage\Exceptions\MissingContentException;
use Exonet\SecureMessage\Factory as SecureMessageFactory;
use Exonet\SecureMessage\Laravel\Database\SecureMessage as SecureMessageModel;
use Exonet\SecureMessage\Laravel\Events\DecryptionFailed;
use Exonet\SecureMessage\Laravel\Events\HitPointLimitReached;
use Exonet\SecureMessage\Laravel\Events\SecureMessageExpired;
use Exonet\SecureMessage\SecureMessage;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Events\Dispatcher as Event;
use Illuminate\Contracts\Filesystem\Factory as Storage;
use Illuminate\Contracts\Filesystem\Filesystem;
use Symfony\Component\HttpFoundation\File\UploadedFile;

class Factory
{
    /**
     * @var string The path prefix for encrypted file contents on the files disk. Must never be empty:
     *             when the files disk and the storage-key disk point at the same location, blobs
     *             stored at the bare message ID would overwrite the storage key files.
     */
    private const FILES_PATH_PREFIX = 'files/';

    /**
     * @var SecureMessageFactory The Secure Message factory, configured with the meta key.
     */
    private SecureMessageFactory $secureMessageFactory;

    /**
     * @var Filesystem The Laravel storage disk holding the storage keys.
     */
    private Filesystem $storage;

    /**
     * @var Storage The Laravel storage factory, kept to lazily resolve the files disk.
     */
    private Storage $storageFactory;

    /**
     * @var Filesystem|null The Laravel storage disk holding encrypted file contents. Resolved lazily
     *                      (see filesDisk()) so installations that never use file messages do not
     *                      need to configure the disk.
     */
    private ?Filesystem $filesDisk = null;

    /**
     * Factory constructor.
     *
     * @param SecureMessageFactory $secureMessageFactory The Secure Message factory.
     * @param Storage              $storage              The Laravel storage factory instance.
     * @param Encrypter            $laravelEncryption    The Laravel Encrypter instance.
     * @param Config               $config               The Laravel configuration instance.
     * @param Event                $event                The Laravel event dispatcher instance.
     *
     * @throws InvalidKeyLengthException If the specified meta key isn't
     *                                   exactly 10 characters.
     */
    public function __construct(
        SecureMessageFactory $secureMessageFactory,
        Storage $storage,
        private readonly Encrypter $laravelEncryption,
        private readonly Config $config,
        private readonly Event $event
    ) {
        $this->secureMessageFactory = $secureMessageFactory->setMetaKey($config->get('secure_messages.meta_key'));
        $this->storage = $storage->disk($config->get('secure_messages.storage_disk_name'));
        $this->storageFactory = $storage;
    }

    /**
     * Encrypt the given content and get a SecureMessage with the verification code available (all other keys are
     * removed from the class).
     *
     * @param string      $content    The content to store secure.
     * @param Carbon|null $expireDate The expire date of the secure message. (Optional)
     * @param int|null    $hitPoints  The number of hit points. (Optional)
     *
     * @return SecureMessage The secure message.
     */
    public function encrypt(string $content, ?Carbon $expireDate = null, ?int $hitPoints = null): SecureMessage
    {
        // Get a Carbon instance with the expire date, based on the argument or on the config setting.
        $carbonExpire = $expireDate ?? Carbon::now()->addDays($this->config->get('secure_messages.expires_in'));
        $hitPoints = $hitPoints ?? $this->config->get('secure_messages.hit_points');

        // Create the secure message.
        $encryptedData = $this->secureMessageFactory
            ->make($content, $hitPoints, $carbonExpire->timestamp)
            ->encrypt();

        // Encrypt the 'storage key' part and save it to the defined storage disk.
        $this->storage->put(
            $encryptedData->getId(),
            $this->laravelEncryption->encrypt($encryptedData->getStorageKey())
        );

        // Save the secure message (encrypted) to the database.
        $record = new SecureMessageModel();
        $record->id = $encryptedData->getId();
        $record->meta = $this->laravelEncryption->encrypt($encryptedData->getEncryptedMeta());
        $record->content = $this->laravelEncryption->encrypt($encryptedData->getEncryptedContent());
        $record->key = $this->laravelEncryption->encrypt($encryptedData->getDatabaseKey());
        $record->created_at = Carbon::now();
        $record->updated_at = Carbon::now();
        $record->save();

        // Wipe the keys from memory, but keep the verification code.
        $encryptedData->wipeKeysFromMemory(false);

        return $encryptedData;
    }

    /**
     * Encrypt the given file and get a SecureMessage with the verification code available (all other
     * keys are removed from the class). The encrypted file contents are stored on the configured
     * files disk; the database record is stored with a null content column.
     *
     * @param \SplFileInfo|string $file       The file to store secure: a path, or an SplFileInfo
     *                                        instance (uploaded files work out of the box).
     * @param Carbon|null         $expireDate The expire date of the secure message. (Optional)
     * @param int|null            $hitPoints  The number of hit points. (Optional)
     * @param string|null         $fileName   The file name to store in the (encrypted) meta data.
     *                                        Defaults to the original client name for uploaded files,
     *                                        or the base name of the path.
     *
     * @throws InvalidFileException If the file is not readable or exceeds the configured maximum size.
     *
     * @return SecureMessage The secure message.
     */
    public function encryptFile(\SplFileInfo|string $file, ?Carbon $expireDate = null, ?int $hitPoints = null, ?string $fileName = null): SecureMessage
    {
        $path = $file instanceof \SplFileInfo ? $file->getPathname() : $file;

        // For uploaded files, default to the name of the file on the client machine. The mime type is
        // always detected server side from the file contents, because the client mime type is not
        // trustworthy.
        if ($fileName === null && $file instanceof UploadedFile) {
            $fileName = $file->getClientOriginalName();
        }

        if (!is_file($path) || !is_readable($path)) {
            throw new InvalidFileException(sprintf('The file [%s] does not exist or is not readable.', $path));
        }

        // Check the file size before reading the contents into memory.
        $maxFileSize = $this->config->get('secure_messages.max_file_size');
        if ($maxFileSize !== null && filesize($path) > $maxFileSize) {
            throw new InvalidFileException(sprintf('The file exceeds the maximum size of %d bytes.', $maxFileSize));
        }

        // Get a Carbon instance with the expire date, based on the argument or on the config setting.
        $carbonExpire = $expireDate ?? Carbon::now()->addDays($this->config->get('secure_messages.expires_in'));
        $hitPoints = $hitPoints ?? $this->config->get('secure_messages.hit_points');

        // Create the secure message.
        $encryptedData = $this->secureMessageFactory
            ->makeFile($path, $hitPoints, $carbonExpire->timestamp, $fileName)
            ->encrypt();

        // Encrypt the 'storage key' part and save it to the defined storage disk.
        $this->storage->put(
            $encryptedData->getId(),
            $this->laravelEncryption->encrypt($encryptedData->getStorageKey())
        );

        // Encrypt the file contents a second time and store the blob on the files disk.
        $this->filesDisk()->put(
            self::FILES_PATH_PREFIX.$encryptedData->getId(),
            $this->laravelEncryption->encrypt($encryptedData->getEncryptedContent())
        );

        // Save the secure message (encrypted) to the database. The content column is null: it marks
        // the record as a file message, whose encrypted contents live on the files disk.
        $record = new SecureMessageModel();
        $record->id = $encryptedData->getId();
        $record->meta = $this->laravelEncryption->encrypt($encryptedData->getEncryptedMeta());
        $record->content = null;
        $record->key = $this->laravelEncryption->encrypt($encryptedData->getDatabaseKey());
        $record->created_at = Carbon::now();
        $record->updated_at = Carbon::now();
        $record->save();

        // Wipe the keys from memory, but keep the verification code.
        $encryptedData->wipeKeysFromMemory(false);

        return $encryptedData;
    }

    /**
     * Return the decrypted content of the secure message for the given message ID.
     *
     * @param string $secureMessageId  The secure message ID.
     * @param string $verificationCode The verification code for the secure message.
     *
     * @throws DecryptException        If the secure message can not be decrypted.
     * @throws MissingContentException If the storage key file or the file blob can not be found.
     *
     * @return string|null The contents of the secure message.
     */
    public function decrypt(string $secureMessageId, string $verificationCode): ?string
    {
        return $this->decryptMessage($secureMessageId, $verificationCode)->getContent();
    }

    /**
     * Return the decrypted SecureMessage class. If the hit point limit is reached, the message is expired, the
     * verification code is wrong or the file containing the storage key can not be found, a DecryptException is thrown.
     * In case of the hit point limit or expired message, the corresponding events are dispatched. For all other errors,
     * the more generic 'DecryptionFailed' event is dispatched.
     *
     * @param string $secureMessageId  The secure message ID.
     * @param string $verificationCode The verification code for the secure message.
     *
     * @throws DecryptException        If the secure message can not be decrypted.
     * @throws MissingContentException If the storage key file or the file blob can not be found.
     *
     * @return SecureMessage The decrypted secure message, with the keys removed.
     */
    public function decryptMessage(string $secureMessageId, string $verificationCode): SecureMessage
    {
        // Get the secure message from the database.
        $record = SecureMessageModel::where('id', $secureMessageId)->firstOrFail();

        // Build the SecureMessage as required by the Crypto utility.
        $secureMessage = new SecureMessage();
        $secureMessage->setId($record->id);
        $secureMessage->setVerificationCode($verificationCode);
        $secureMessage->setDatabaseKey($this->laravelEncryption->decrypt($record->key));
        $secureMessage->setEncryptedMeta($this->laravelEncryption->decrypt($record->meta));

        try {
            // Load the encrypted content, from the files disk or the database record. This must
            // happen before decrypting, also for the failure paths.
            $this->loadEncryptedContent($secureMessage, $record);

            // Check if the storage key file exists.
            if (!$this->storage->exists($record->id)) {
                throw new MissingContentException('Can not find key file.');
            }

            // Read and set the storage key.
            $secureMessage->setStorageKey($this->laravelEncryption->decrypt($this->storage->get($record->id)));

            // Try decrypting the secure message.
            return $this->secureMessageFactory->decrypt($secureMessage);
        } catch (DecryptException $exception) {
            // Catch the exception and update the secure message, if it is set.
            if ($exception->secureMessage !== null) {
                $record->meta = $this->laravelEncryption->encrypt($exception->secureMessage->getEncryptedMeta());
                $record->save();
            }

            // Wipe the keys before the secure message is handed to event listeners. Most failure paths
            // already wipe the keys (the DecryptException constructor does so when it is given the secure
            // message), but the paths that throw without it - a missing key file, a missing file blob or
            // malformed stored ciphertext - would otherwise expose the decrypted keys on this instance to
            // listeners (and to anything they serialize the event to, such as a queue).
            $secureMessage->wipeKeysFromMemory();

            // Dispatch events.
            match ($exception::class) {
                HitPointLimitReachedException::class => $this->event->dispatch(new HitPointLimitReached($secureMessage)),
                ExpiredException::class => $this->event->dispatch(new SecureMessageExpired($secureMessage)),
                default => $this->event->dispatch(new DecryptionFailed($secureMessage)),
            };

            // And throw the exception again, so the user can catch it.
            throw $exception;
        }
    }

    /**
     * @param string $secureMessageId  The secure message ID.
     * @param string $verificationCode The verification code for the secure message.
     *
     * @throws DecryptException        If the encrypted content is malformed.
     * @throws MissingContentException If the storage key file or the file blob can not be found.
     *
     * @return bool Whether or not the verification code is valid.
     */
    public function checkVerificationCode(string $secureMessageId, string $verificationCode): bool
    {
        // Get the secure message from the database.
        $record = SecureMessageModel::where('id', $secureMessageId)->firstOrFail();

        // Build the SecureMessage as required by the Crypto utility.
        $secureMessage = new SecureMessage();
        $secureMessage->setId($record->id);
        $secureMessage->setVerificationCode($verificationCode);
        $secureMessage->setDatabaseKey($this->laravelEncryption->decrypt($record->key));
        $secureMessage->setEncryptedMeta($this->laravelEncryption->decrypt($record->meta));
        $this->loadEncryptedContent($secureMessage, $record);

        // Check if the storage key file exists.
        if (!$this->storage->exists($record->id)) {
            throw new MissingContentException('Can not find key file.');
        }

        // Read and set the storage key.
        $secureMessage->setStorageKey($this->laravelEncryption->decrypt($this->storage->get($record->id)));

        return $this->secureMessageFactory->validateEncryptionKey($secureMessage);
    }

    /**
     * Get only the meta data of the secure message. Useful to check the hit points or expire date.
     *
     * @param string $secureMessageId The secure message ID.
     *
     * @throws DecryptException        If the meta data can not be decrypted.
     * @throws MissingContentException If the storage key file can not be found.
     *
     * @return SecureMessage The secure message with only the (decrypted) meta.
     */
    public function getMeta(string $secureMessageId): SecureMessage
    {
        // Get the secure message from the database.
        $record = SecureMessageModel::where('id', $secureMessageId)->firstOrFail();

        // Build the SecureMessage as required by the Crypto utility, but only with the data for decrypting the meta.
        $secureMessage = new SecureMessage();
        $secureMessage->setId($record->id);
        $secureMessage->setDatabaseKey($this->laravelEncryption->decrypt($record->key));
        $secureMessage->setEncryptedMeta($this->laravelEncryption->decrypt($record->meta));

        // Check if the storage key file exists.
        if (!$this->storage->exists($record->id)) {
            throw new MissingContentException('Can not find key file.');
        }

        // Read and set the storage key.
        $secureMessage->setStorageKey($this->laravelEncryption->decrypt($this->storage->get($record->id)));

        // Decrypt the meta data.
        $meta = $this->secureMessageFactory->decryptMeta($secureMessage);

        // Remove all keys from memory.
        $secureMessage->wipeKeysFromMemory();
        $secureMessage->wipeEncryptedMetaFromMemory();

        // Return the secure message (with only the meta data set).
        return $meta;
    }

    /**
     * Destroy a secure message. Both the record and the key in the file storage will be removed.
     *
     * @param string $secureMessageId The secure message ID.
     */
    public function destroy(string $secureMessageId): void
    {
        // For file messages the encrypted contents live on the files disk; remove that blob as well.
        // The record is fetched first so the files disk is only resolved for file messages.
        $record = SecureMessageModel::find($secureMessageId);
        if ($record !== null && $record->content === null) {
            $this->filesDisk()->delete(self::FILES_PATH_PREFIX.$secureMessageId);
        }

        SecureMessageModel::destroy($secureMessageId);
        $this->storage->delete($secureMessageId);
    }

    /**
     * Set the encrypted content on the secure message: from the database record, or for file
     * messages (identified by a null content column) from the blob on the files disk.
     *
     * @param SecureMessage      $secureMessage The secure message to set the encrypted content on.
     * @param SecureMessageModel $record        The database record.
     *
     * @throws MissingContentException If the file blob can not be found.
     */
    private function loadEncryptedContent(SecureMessage $secureMessage, SecureMessageModel $record): void
    {
        if ($record->content !== null) {
            $secureMessage->setEncryptedContent($this->laravelEncryption->decrypt($record->content));

            return;
        }

        // File message: the encrypted contents are stored on the files disk.
        if (!$this->filesDisk()->exists(self::FILES_PATH_PREFIX.$record->id)) {
            throw new MissingContentException('Can not find file blob.');
        }

        $secureMessage->setEncryptedContent(
            $this->laravelEncryption->decrypt($this->filesDisk()->get(self::FILES_PATH_PREFIX.$record->id))
        );
    }

    /**
     * Get the disk holding the encrypted file contents. Resolved lazily (and memoized), so that
     * installations that never use file messages do not need to configure the disk.
     *
     * @return Filesystem The files disk.
     */
    private function filesDisk(): Filesystem
    {
        return $this->filesDisk ??= $this->storageFactory->disk($this->config->get('secure_messages.files_disk_name'));
    }
}
