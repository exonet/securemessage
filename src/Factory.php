<?php

namespace Exonet\SecureMessage;

use Exonet\SecureMessage\Exceptions\InvalidKeyLengthException;

class Factory
{
    /**
     * @const int The number of seconds the secure message is valid.
     */
    protected const DEFAULT_EXPIRE = 86400;
    /**
     * @var SecureMessage The SecureMessage class.
     */
    public $secureMessage;

    /**
     * @var string The key to decrypt the meta data.
     */
    private $metaKey;

    /**
     * @var Crypto The crypto utility.
     */
    private $crypto;

    /**
     * Factory constructor.
     *
     * @param string      $metaKey The meta key to use.
     * @param Crypto|null $crypto  The instance of the crypto utility to use.
     */
    public function __construct(?string $metaKey = null, ?Crypto $crypto = null)
    {
        if ($metaKey !== null) {
            $this->setMetaKey($metaKey);
        }

        $this->setCryptoInstance($crypto ?? new Crypto());
    }

    /**
     * Make a new secure message factory.
     *
     * @param string $content   The content to encrypt.
     * @param int    $hitPoints The number of hit points.
     * @param int    $expiresAt The expire timestamp.
     *
     * @return Factory The new (yet unencrypted) secure message factory.
     */
    public function make(string $content, int $hitPoints = 3, ?int $expiresAt = null): self
    {
        $factory = $this->createFactoryInstance();

        $message = new SecureMessage();
        $message->setId($this->generateId());
        $message->setContent($content);
        $message->setHitPoints($hitPoints);
        $message->setExpiresAt($expiresAt ?? time() + self::DEFAULT_EXPIRE);

        $factory->secureMessage = $message;

        return $factory;
    }

    /**
     * Perform the actual encryption on the given secure message or the secure message of the current factory. A
     * SecureMessage instance with the encrypted content and keys are returned. Please note that when a SecureMessage
     * is passed the keys that are already set will be overwritten with new ones.
     *
     * @param SecureMessage|null $secureMessage If set encrypt the given SecureMessage instance.
     *
     * @return SecureMessage The encrypted secure message, including the encryption keys.
     */
    public function encrypt(?SecureMessage $secureMessage = null): SecureMessage
    {
        $message = $secureMessage ?? $this->secureMessage;
        $keys = $this->generateKeys();

        $message->setStorageKey($keys['storage_key']);
        $message->setDatabaseKey($keys['database_key']);
        $message->setVerificationCode($keys['verification_code']);
        $message->setMetaKey($this->metaKey);

        return $this->crypto->encrypt($message);
    }

    /**
     * Decrypt the given secure message. Make sure all keys are set.
     *
     * @param SecureMessage $secureMessage The secure message to decrypt.
     *
     * @throws Exceptions\DecryptException If the message can not be decrypted.
     *
     * @return SecureMessage The decrypted secure message.
     */
    public function decrypt(SecureMessage $secureMessage): SecureMessage
    {
        $secureMessage->setMetaKey($this->metaKey);

        return $this->crypto->decrypt($secureMessage);
    }

    /**
     * Decrypt the meta data of given secure message. Make sure the meta key is set.
     *
     * @param SecureMessage $secureMessage The secure message to decrypt.
     *
     * @throws Exceptions\DecryptException If the message can not be decrypted.
     *
     * @return SecureMessage The decrypted secure message.
     */
    public function decryptMeta(SecureMessage $secureMessage): SecureMessage
    {
        $secureMessage->setMetaKey($this->metaKey);

        return $this->crypto->decryptMeta($secureMessage);
    }

    /**
     * Check if the set encryption key can be used to decrypt te message.
     *
     * @param SecureMessage $secureMessage The secure message to decrypt.
     *
     * @return bool Whether or not the encryption key is valid.
     */
    public function validateEncryptionKey(SecureMessage $secureMessage): bool
    {
        $secureMessage->setMetaKey($this->metaKey);

        return $this->crypto->validateEncryptionKey($secureMessage);
    }

    /**
     * Set the key to encrypt and decrypt the meta data. Must be 10 characters.
     *
     * @param string $key The key.
     *
     * @throws InvalidKeyLengthException If the key isn't 10 characters long.
     *
     * @return $this The current factory instance.
     */
    public function setMetaKey(string $key): self
    {
        if (strlen($key) !== 10) {
            throw new InvalidKeyLengthException('The meta key must be 10 characters.');
        }

        $this->metaKey = $key;

        return $this;
    }

    /**
     * Set the crypto instance to use.
     *
     * @param Crypto $crypto The crypto instance to use.
     *
     * @return $this The current factory instance.
     */
    public function setCryptoInstance(Crypto $crypto): self
    {
        $this->crypto = $crypto;

        return $this;
    }

    /**
     * Create a new factory instance.
     *
     * @return static The new factory instance.
     */
    protected function createFactoryInstance()
    {
        return new static($this->metaKey);
    }

    /**
     * Generate an ID for the secure message.
     *
     * @return string The ID to use.
     */
    protected function generateId(): string
    {
        return strtoupper(substr(sha1(random_bytes(24)), 0, 32));
    }

    /**
     * Create three keys (with a length of 32 bytes in total) that will be used to encrypt the message. The keys are
     * divided in three parts, so they can be stored at three different locations.
     *
     * @return array The keys to use as encryption key.
     */
    protected function generateKeys(): array
    {
        $verificationCode = substr(sha1(random_bytes(10)), 0, 10);
        $storageKey = random_bytes(11);
        $databaseKey = random_bytes(11);

        return [
            'storage_key' => $storageKey,
            'database_key' => $databaseKey,
            'verification_code' => $verificationCode,
        ];
    }
}
