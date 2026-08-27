<?php

declare(strict_types=1);

namespace Exonet\SecureMessage;

use Exonet\SecureMessage\Exceptions\InvalidFileException;

class SecureMessage
{
    /**
     * @var string|null The message ID.
     */
    private ?string $id = null;

    /**
     * @var array<string, string|null> Array holding the different keys used for this secure message.
     *
     * Note: these keys are wiped with sodium_memzero(), which nulls its by-reference argument. The
     * array values must therefore always allow null.
     */
    private array $keys = ['database' => null, 'storage' => null, 'verification' => null, 'meta' => null];

    /**
     * @var string|null The message content. Can be plain text or encrypted. Nullable because it is
     *                  wiped with sodium_memzero(), which nulls its by-reference argument.
     */
    private ?string $content = null;

    /**
     * @var string|null The encrypted version of the content. Nullable because it is wiped with
     *                  sodium_memzero(), which nulls its by-reference argument.
     */
    private ?string $contentEncrypted = null;

    /**
     * @var array<string, int|string|null> The meta data for this secure message. Holds the hit points and expire
     *                                     timestamp, and for file messages also the file name, mime type and file
     *                                     size.
     */
    private array $meta = ['hit_points' => null, 'expires_at' => null];

    /**
     * @var string|null The encrypted version of the meta. Nullable because it is wiped with
     *                  sodium_memzero(), which nulls its by-reference argument.
     */
    private ?string $metaEncrypted = null;

    /**
     * Wipe the sensitive keys from memory.
     *
     * @param bool $wipeVerificationCode When true, wipe also the verification code.
     */
    public function wipeKeysFromMemory(bool $wipeVerificationCode = true): void
    {
        if ($this->keys['database'] !== null) {
            sodium_memzero($this->keys['database']);
        }

        if ($this->keys['storage'] !== null) {
            sodium_memzero($this->keys['storage']);
        }

        if ($this->keys['meta'] !== null) {
            sodium_memzero($this->keys['meta']);
        }

        if ($wipeVerificationCode && $this->keys['verification'] !== null) {
            sodium_memzero($this->keys['verification']);
        }
    }

    /**
     * Wipe the plain text content from memory.
     */
    public function wipeContentFromMemory(): void
    {
        if ($this->content !== null) {
            sodium_memzero($this->content);
        }
    }

    /**
     * Wipe the encrypted content from memory.
     */
    public function wipeEncryptedContentFromMemory(): void
    {
        if ($this->contentEncrypted !== null) {
            sodium_memzero($this->contentEncrypted);
        }
    }

    /**
     * Wipe the encrypted meta from memory.
     */
    public function wipeEncryptedMetaFromMemory(): void
    {
        if ($this->metaEncrypted !== null) {
            sodium_memzero($this->metaEncrypted);
        }
    }

    /**
     * Get the encryption key.
     *
     * @return string The encryption key.
     */
    public function getEncryptionKey(): string
    {
        return $this->getDatabaseKey().$this->getStorageKey().$this->getVerificationCode();
    }

    /**
     * Get the meta key.
     *
     * @return string|null The meta key.
     */
    public function getMetaKey(): ?string
    {
        if ($this->getDatabaseKey() !== null && $this->getStorageKey() !== null && $this->keys['meta'] !== null) {
            return $this->getDatabaseKey().$this->getStorageKey().$this->keys['meta'];
        }

        return null;
    }

    /**
     * Set the meta key.
     *
     * @param string $key The meta key.
     *
     * @return $this The current secure message instance.
     */
    public function setMetaKey(string $key): self
    {
        $this->keys['meta'] = $key;

        return $this;
    }

    /**
     * Get the secure message ID.
     *
     * @return string|null The secure message ID.
     */
    public function getId(): ?string
    {
        return $this->id;
    }

    /**
     * Set the secure message ID.
     *
     * @param string $id The secure message ID.
     *
     * @return $this The current secure message instance.
     */
    public function setId(string $id): self
    {
        $this->id = $id;

        return $this;
    }

    /**
     * Check if the content is already encrypted.
     *
     * @return bool True when the content is encrypted.
     */
    public function isContentEncrypted(): bool
    {
        return $this->contentEncrypted !== null;
    }

    /**
     * Set the encrypted content.
     *
     * @param string $encrypted The encrypted content.
     *
     * @return $this The current secure message instance.
     */
    public function setEncryptedContent(string $encrypted): self
    {
        $this->contentEncrypted = $encrypted;

        return $this;
    }

    /**
     * Get the encrypted content data of this message.
     *
     * @return string|null The encrypted content data.
     */
    public function getEncryptedContent(): ?string
    {
        return $this->contentEncrypted;
    }

    /**
     * Check if the meta is already encrypted.
     *
     * @return bool True when the meta is encrypted.
     */
    public function isMetaEncrypted(): bool
    {
        return $this->metaEncrypted !== null;
    }

    /**
     * Set the encrypted meta data.
     *
     * @param string $encrypted The encrypted meta data.
     *
     * @return $this The current secure message instance.
     */
    public function setEncryptedMeta(string $encrypted): self
    {
        $this->metaEncrypted = $encrypted;

        return $this;
    }

    /**
     * Get the encrypted meta data of this message.
     *
     * @return string|null The encrypted meta data.
     */
    public function getEncryptedMeta(): ?string
    {
        return $this->metaEncrypted;
    }

    /**
     * Get the content. Can be encrypted or unencrypted.
     *
     * @return string|null The content.
     */
    public function getContent(): ?string
    {
        return $this->content;
    }

    /**
     * Set the content. Can be encrypted or unencrypted.
     *
     * @param string $content The content.
     *
     * @return $this The current secure message instance.
     */
    public function setContent(string $content): self
    {
        $this->content = $content;

        return $this;
    }

    /**
     * Get the verification code.
     *
     * @return string|null The verification code.
     */
    public function getVerificationCode(): ?string
    {
        return $this->keys['verification'];
    }

    /**
     * Set the verification code.
     *
     * @param string $verificationCode The verification code.
     *
     * @return $this The current secure message instance.
     */
    public function setVerificationCode(string $verificationCode): self
    {
        $this->keys['verification'] = $verificationCode;

        return $this;
    }

    /**
     * Get the storage key.
     *
     * @return string|null The storage key.
     */
    public function getStorageKey(): ?string
    {
        return $this->keys['storage'];
    }

    /**
     * Set the storage key.
     *
     * @param string $storageKey The storage key.
     *
     * @return $this The current secure message instance.
     */
    public function setStorageKey(string $storageKey): self
    {
        $this->keys['storage'] = $storageKey;

        return $this;
    }

    /**
     * Get the database key.
     *
     * @return string|null The database key.
     */
    public function getDatabaseKey(): ?string
    {
        return $this->keys['database'];
    }

    /**
     * Set the database key.
     *
     * @param string $databaseKey The database key.
     *
     * @return $this The current secure message instance.
     */
    public function setDatabaseKey(string $databaseKey): self
    {
        $this->keys['database'] = $databaseKey;

        return $this;
    }

    /**
     * Set the maximum number of hit points.
     *
     * @param int $hitPoints The number of hit points.
     *
     * @return $this The current secure message instance.
     */
    public function setHitPoints(int $hitPoints): self
    {
        $this->meta['hit_points'] = $hitPoints;

        return $this;
    }

    /**
     * Get the maximum number of hit points.
     *
     * @return int The maximum number of hit points.
     */
    public function getHitPoints(): int
    {
        return $this->meta['hit_points'];
    }

    /**
     * Set the expire date of this message.
     *
     * @param int $expiresAt The timestamp when this message expires.
     *
     * @return $this The current secure message instance.
     */
    public function setExpiresAt(int $expiresAt): self
    {
        $this->meta['expires_at'] = $expiresAt;

        return $this;
    }

    /**
     * Get the expire date of this message.
     *
     * @return int The timestamp when this message expires.
     */
    public function getExpiresAt(): int
    {
        return $this->meta['expires_at'];
    }

    /**
     * Get all meta data for this message.
     *
     * @return mixed[] The meta data.
     */
    public function getMeta(): array
    {
        return $this->meta;
    }

    /**
     * Set all meta data for this message. The hit points and expire timestamp are cast to integers
     * to keep the (strictly typed) meta getters working for callers that provide numeric strings.
     *
     * @param mixed[] $metaData The meta data.
     *
     * @return $this The current secure message instance.
     */
    public function setMeta(array $metaData): self
    {
        if (isset($metaData['hit_points'])) {
            $metaData['hit_points'] = (int) $metaData['hit_points'];
        }

        if (isset($metaData['expires_at'])) {
            $metaData['expires_at'] = (int) $metaData['expires_at'];
        }

        if (isset($metaData['file_size'])) {
            $metaData['file_size'] = (int) $metaData['file_size'];
        }

        $this->meta = $metaData;

        return $this;
    }

    /**
     * Check if this secure message is a file.
     *
     * @return bool True when this secure message holds a file.
     */
    public function isFile(): bool
    {
        return isset($this->meta['file_name']);
    }

    /**
     * Set the file name of this message. Setting a file name marks the message as a file.
     *
     * @param string $fileName The file name.
     *
     * @throws InvalidFileException If the file name is not valid UTF-8 (required because the meta
     *                              data is JSON encoded before it is encrypted).
     *
     * @return $this The current secure message instance.
     */
    public function setFileName(string $fileName): self
    {
        // UTF-8 validation via PCRE instead of mb_check_encoding: mbstring is not a package dependency.
        if (preg_match('//u', $fileName) !== 1) {
            throw new InvalidFileException('The file name must be valid UTF-8.');
        }

        $this->meta['file_name'] = $fileName;

        return $this;
    }

    /**
     * Get the file name of this message.
     *
     * @return string|null The file name, or null when this message is not a file.
     */
    public function getFileName(): ?string
    {
        $fileName = $this->meta['file_name'] ?? null;

        return is_string($fileName) ? $fileName : null;
    }

    /**
     * Set the mime type of the file.
     *
     * @param string $mimeType The mime type.
     *
     * @throws InvalidFileException If the mime type is not valid UTF-8 (required because the meta
     *                              data is JSON encoded before it is encrypted).
     *
     * @return $this The current secure message instance.
     */
    public function setMimeType(string $mimeType): self
    {
        // UTF-8 validation via PCRE instead of mb_check_encoding: mbstring is not a package dependency.
        if (preg_match('//u', $mimeType) !== 1) {
            throw new InvalidFileException('The mime type must be valid UTF-8.');
        }

        $this->meta['mime_type'] = $mimeType;

        return $this;
    }

    /**
     * Get the mime type of the file.
     *
     * @return string|null The mime type, or null when this message is not a file.
     */
    public function getMimeType(): ?string
    {
        $mimeType = $this->meta['mime_type'] ?? null;

        return is_string($mimeType) ? $mimeType : null;
    }

    /**
     * Set the file size in bytes.
     *
     * @param int $fileSize The file size in bytes.
     *
     * @return $this The current secure message instance.
     */
    public function setFileSize(int $fileSize): self
    {
        $this->meta['file_size'] = $fileSize;

        return $this;
    }

    /**
     * Get the file size in bytes.
     *
     * @return int|null The file size in bytes, or null when this message is not a file.
     */
    public function getFileSize(): ?int
    {
        $fileSize = $this->meta['file_size'] ?? null;

        return is_int($fileSize) ? $fileSize : null;
    }
}
