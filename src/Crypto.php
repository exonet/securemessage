<?php

namespace Exonet\SecureMessage;

use Exonet\SecureMessage\Exceptions\DecryptException;
use Exonet\SecureMessage\Exceptions\ExpiredException;
use Exonet\SecureMessage\Exceptions\HitPointLimitReachedException;
use Exonet\SecureMessage\Exceptions\InvalidKeyLengthException;

class Crypto
{
    /**
     * Encrypt the given content with the specified key. A base64 string will be returned with a JSON encoded array that
     * contains both the nonce and the encrypted content. The nonce doesn't have to be confidential, but it should never
     * ever be reused with the same key, so it is randomly generated.
     *
     * @param SecureMessage $secureMessage The secure message to encrypt.
     *
     * @throws InvalidKeyLengthException If the specified key isn't 32 bytes.
     *
     * @return SecureMessage The encrypted version of the SecureMessage instance.
     */
    public function encrypt(SecureMessage $secureMessage) : SecureMessage
    {
        if ($secureMessage->isMetaEncrypted() === false) {
            if (strlen($secureMessage->getMetaKey()) !== 32) {
                throw new InvalidKeyLengthException('The key must be 32 bytes/characters.');
            }

            $metaNonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $encryptedMeta = sodium_crypto_secretbox(
                json_encode($secureMessage->getMeta()),
                $metaNonce,
                $secureMessage->getMetaKey()
            );

            $secureMessage->setEncryptedMeta($this->toString($metaNonce, $encryptedMeta));
        }

        if ($secureMessage->isContentEncrypted() === false) {
            if (strlen($secureMessage->getEncryptionKey()) !== 32) {
                throw new InvalidKeyLengthException('The key must be 32 bytes/characters.');
            }

            $contentNonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $encryptedContent = sodium_crypto_secretbox(
                $secureMessage->getContent(),
                $contentNonce,
                $secureMessage->getEncryptionKey()
            );
            $secureMessage->setEncryptedContent($this->toString($contentNonce, $encryptedContent));
            $secureMessage->wipeContentFromMemory();
        }

        return $secureMessage;
    }

    /**
     * Decrypt the content of a secure message.
     *
     * @param SecureMessage $secureMessage The secure message to decrypt.
     *
     * @throws DecryptException              When the content can not be decrypted.
     * @throws ExpiredException              When the secure message is expired.
     * @throws HitPointLimitReachedException When the secure message hit point limit is reached.
     *
     * @return SecureMessage The decrypted SecureMessage.
     */
    public function decrypt(SecureMessage $secureMessage) : SecureMessage
    {
        // If the meta isn't decrypted yet, decrypt it now.
        if ($secureMessage->isMetaEncrypted()) {
            $secureMessage = $this->decryptMeta($secureMessage);
        }

        if (strlen($secureMessage->getEncryptionKey()) !== 32) {
            $secureMessage = $this->reduceHitPoints($secureMessage);

            throw new DecryptException('Invalid key length.', $secureMessage);
        }

        // Check if the message is expired.
        if (time() > $secureMessage->getExpiresAt()) {
            throw new ExpiredException('This secure message is expired.', $secureMessage);
        }

        // Check if the message is out of hit points.
        if ($secureMessage->getHitPoints() <= 0) {
            $this->reduceHitPoints($secureMessage);
        }

        $contentParts = $this->fromString($secureMessage->getEncryptedContent());
        $content = sodium_crypto_secretbox_open(
            $contentParts['data'],
            $contentParts['nonce'],
            $secureMessage->getEncryptionKey()
        );

        if ($content === false) {
            $secureMessage = $this->reduceHitPoints($secureMessage);

            throw new DecryptException('Unable to or failed decrypt the contents of the message.', $secureMessage);
        }

        $secureMessage->setContent($content);
        $secureMessage->wipeEncryptedContentFromMemory();
        $secureMessage->wipeKeysFromMemory();

        return $secureMessage;
    }

    /**
     * Check if the encryption key can be used to decrypt the message.
     *
     * @param SecureMessage $secureMessage
     *
     * @return bool Whether or not the encryption key is valid.
     */
    public function validateEncryptionKey(SecureMessage $secureMessage) : bool
    {
        if (strlen($secureMessage->getEncryptionKey()) !== 32 || strlen($secureMessage->getMetaKey()) !== 32) {
            return false;
        }

        $contentParts = $this->fromString($secureMessage->getEncryptedContent());
        // There's no other way to check if a key is valid than decrypting the content.
        $content = sodium_crypto_secretbox_open(
            $contentParts['data'],
            $contentParts['nonce'],
            $secureMessage->getEncryptionKey()
        );

        $keyIsValid = $content !== false;

        // Remove the decrypted data from memory.
        if (is_string($content)) {
            sodium_memzero($content);
        }

        return $keyIsValid;
    }

    /**
     * Decrypt the meta data of secure message. Make sure the encrypted meta field and the meta key are set.
     *
     * @param SecureMessage $secureMessage The secure message to decrypt.
     *
     * @throws DecryptException When the content can not be decrypted.
     *
     * @return SecureMessage The decrypted SecureMessage.
     */
    public function decryptMeta(SecureMessage $secureMessage) : SecureMessage
    {
        if (!$secureMessage->isMetaEncrypted() || strlen($secureMessage->getMetaKey()) !== 32) {
            throw new DecryptException('Unable to or failed to decrypt the meta data.', $secureMessage);
        }

        $metaParts = $this->fromString($secureMessage->getEncryptedMeta());
        $metaData = sodium_crypto_secretbox_open(
            $metaParts['data'],
            $metaParts['nonce'],
            $secureMessage->getMetaKey()
        );

        if ($metaData === false) {
            throw new DecryptException('Unable to or failed to decrypt the meta data.', $secureMessage);
        }

        $secureMessage->setMeta(json_decode($metaData, true));
        $secureMessage->wipeEncryptedMetaFromMemory();

        return $secureMessage;
    }

    /**
     * Merge the used nonce and the encrypted content into a single base64 string.
     *
     * @param string $nonce            The nonce that was used.
     * @param string $encryptedContent The encrypted content.
     *
     * @return string The merged string.
     */
    private function toString(string $nonce, string $encryptedContent) : string
    {
        return base64_encode(json_encode([base64_encode($nonce), base64_encode($encryptedContent)]));
    }

    /**
     * Transform the base64 encoded string back to a nonce and encrypted message.
     *
     * @param string $content The base64 string as generated by $this->toString().
     *
     * @return string[] The nonce and the encrypted message.
     */
    private function fromString(string $content) : array
    {
        [$nonce, $message] = json_decode(base64_decode($content, true));

        return ['nonce' => base64_decode($nonce, true), 'data' => base64_decode($message, true)];
    }

    /**
     * Reduce the number of hit points with 1 in the given secure message. If the new value is 0, a
     * HitPointLimitReachedException is thrown.
     *
     * @param SecureMessage $secureMessage The secure message.
     *
     * @throws HitPointLimitReachedException If there are no hit points remaining.
     *
     * @return SecureMessage The secure message with the hit points reduces by 1.
     */
    private function reduceHitPoints(SecureMessage $secureMessage) : SecureMessage
    {
        $secureMessage->setHitPoints($secureMessage->getHitPoints() - 1);
        if ($secureMessage->getHitPoints() <= 0) {
            throw new HitPointLimitReachedException(
                'The maximum number of hit points has been reached.', $secureMessage
            );
        }

        return $secureMessage;
    }
}
