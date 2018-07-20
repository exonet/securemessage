<?php

namespace Exonet\SecureMessage\Laravel;

use Carbon\Carbon;
use Exonet\SecureMessage\Exceptions\DecryptException;
use Exonet\SecureMessage\Exceptions\ExpiredException;
use Exonet\SecureMessage\Exceptions\HitPointLimitReachedException;
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

class Factory
{
    /**
     * @var SecureMessageFactory The Secure Message factory.
     */
    private $secureMessageFactory;

    /**
     * @var Storage The Laravel storage instance.
     */
    private $storage;

    /**
     * @var Encrypter The Laravel Encrypter instance.
     */
    private $laravelEncryption;

    /**
     * @var Config The Laravel configuration instance.
     */
    private $config;

    /**
     * @var Event The Laravel event dispatcher instance.
     */
    private $event;

    /**
     * Factory constructor.
     *
     * @param SecureMessageFactory $secureMessageFactory The Secure Message factory.
     * @param Storage              $storage              The Laravel storage instance.
     * @param Encrypter            $laravelEncryption    The Laravel Encrypter instance.
     * @param Config               $config               The Laravel configuration instance.
     * @param Event                $event                The Laravel event dispatcher instance.
     *
     * @throws \Exonet\SecureMessage\Exceptions\InvalidKeyLengthException If the specified meta key isn't
     *                                                                    exactly 10 characters.
     */
    public function __construct(
        SecureMessageFactory $secureMessageFactory,
        Storage $storage,
        Encrypter $laravelEncryption,
        Config $config,
        Event $event
    ) {
        $this->secureMessageFactory = $secureMessageFactory->setMetaKey($config->get('secure_messages.meta_key'));
        $this->storage = $storage->disk($config->get('secure_messages.storage_disk_name'));
        $this->laravelEncryption = $laravelEncryption;
        $this->config = $config;
        $this->event = $event;
    }

    /**
     * Encrypt the given content and get a SecureMessage with the verification code available (all other keys are
     * removed from the class).
     *
     * @param string      $content    The content to store secure.
     * @param Carbon|null $expireDate The expire date of the secure message. (Optional)
     *
     * @return SecureMessage The secure message.
     */
    public function encrypt(string $content, ?Carbon $expireDate = null, ?int $hitPoints = null) : SecureMessage
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
     * Return the decrypted content of the secure message for the given message ID.
     *
     * @param string $secureMessageId  The secure message ID.
     * @param string $verificationCode The verification code for the secure message.
     *
     * @throws DecryptException If the secure message can not be encrypted.
     *
     * @return string The contents of the secure message.
     */
    public function decrypt(string $secureMessageId, string $verificationCode) : ?string
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
     * @throws DecryptException If the secure message can not be encrypted.
     *
     * @return SecureMessage The decrypted secure message, with the keys removed.
     */
    public function decryptMessage(string $secureMessageId, string $verificationCode) : SecureMessage
    {
        // Get the secure message from the database.
        $record = SecureMessageModel::where('id', $secureMessageId)->firstOrFail();

        // Build the SecureMessage as required by the Crypto utility.
        $secureMessage = new SecureMessage();
        $secureMessage->setId($record->id);
        $secureMessage->setVerificationCode($verificationCode);
        $secureMessage->setDatabaseKey($this->laravelEncryption->decrypt($record->key));
        $secureMessage->setEncryptedMeta($this->laravelEncryption->decrypt($record->meta));
        $secureMessage->setEncryptedContent($this->laravelEncryption->decrypt($record->content));

        try {
            // Check if the storage key file exists.
            if (!$this->storage->exists($record->id)) {
                throw new DecryptException('Can not find key file.');
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

            // Dispatch events.
            switch (get_class($exception)) {
                case HitPointLimitReachedException::class:
                    $this->event->dispatch(new HitPointLimitReached($secureMessage));
                    break;
                case ExpiredException::class:
                    $this->event->dispatch(new SecureMessageExpired($secureMessage));
                    break;
                default:
                    $this->event->dispatch(new DecryptionFailed($secureMessage));
                    break;
            }

            // And throw the exception again, so the user can catch it.
            throw $exception;
        }
    }

    /**
     * @param string $secureMessageId  The secure message ID.
     * @param string $verificationCode The verification code for the secure message.
     *
     * @throws DecryptException If the storage key file can not be found.
     *
     * @return bool Whether or not the verification code is valid.
     */
    public function checkVerificationCode(string $secureMessageId, string $verificationCode) : bool
    {
        // Get the secure message from the database.
        $record = SecureMessageModel::where('id', $secureMessageId)->firstOrFail();

        // Build the SecureMessage as required by the Crypto utility.
        $secureMessage = new SecureMessage();
        $secureMessage->setId($record->id);
        $secureMessage->setVerificationCode($verificationCode);
        $secureMessage->setDatabaseKey($this->laravelEncryption->decrypt($record->key));
        $secureMessage->setEncryptedMeta($this->laravelEncryption->decrypt($record->meta));
        $secureMessage->setEncryptedContent($this->laravelEncryption->decrypt($record->content));

        // Check if the storage key file exists.
        if (!$this->storage->exists($record->id)) {
            throw new DecryptException('Can not find key file.');
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
     * @throws DecryptException If the secure message can not be encrypted.
     *
     * @return SecureMessage The secure message with only the (decrypted) meta.
     */
    public function getMeta(string $secureMessageId) : SecureMessage
    {
        // Get the secure message from the database.
        $record = SecureMessageModel::where('id', $secureMessageId)->firstOrFail();

        // Build the SecureMessage as required by the Crypto utility, but only with the data for decrypting the meta.
        $secureMessage = new SecureMessage();
        $secureMessage->setId($record->id);
        $secureMessage->setEncryptedMeta($this->laravelEncryption->decrypt($record->meta));

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
    public function destroy(string $secureMessageId)
    {
        SecureMessageModel::destroy($secureMessageId);
        $this->storage->delete($secureMessageId);
    }
}
