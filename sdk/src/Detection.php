<?php

declare(strict_types=1);

namespace WebDecoy;

/**
 * Detection Model
 *
 * Represents a bot detection event with all associated signals and metadata.
 */
class Detection
{
    private ?string $id = null;
    private ?string $scannerId = null;
    private ?string $ipAddress = null;
    private ?string $userAgent = null;
    private ?string $referer = null;
    private ?string $url = null;
    private int $clientScore = 0;
    private array $flags = [];
    private array $fingerprint = [];
    private ?string $aiBot = null;
    private ?string $honeypotValue = null;
    private ?string $source = 'bot_scanner';
    private ?string $threatLevel = null;
    private array $metadata = [];
    private ?int $timestamp = null;

    /**
     * Create a Detection from an array of data
     *
     * @param array $data Detection data
     * @return self
     */
    public static function fromArray(array $data): self
    {
        $detection = new self();

        if (isset($data['id'])) {
            $detection->id = $data['id'];
        }
        if (isset($data['scanner_id'])) {
            $detection->scannerId = $data['scanner_id'];
        }
        if (isset($data['ip_address'])) {
            $detection->ipAddress = $data['ip_address'];
        }
        if (isset($data['user_agent'])) {
            $detection->userAgent = $data['user_agent'];
        }
        if (isset($data['referer'])) {
            $detection->referer = $data['referer'];
        }
        if (isset($data['url'])) {
            $detection->url = $data['url'];
        }
        if (isset($data['client_score'])) {
            $detection->clientScore = (int) $data['client_score'];
        }
        if (isset($data['flags'])) {
            $detection->flags = (array) $data['flags'];
        }
        if (isset($data['fingerprint'])) {
            $detection->fingerprint = (array) $data['fingerprint'];
        }
        if (isset($data['ai_bot'])) {
            $detection->aiBot = $data['ai_bot'];
        }
        if (isset($data['honeypot_value'])) {
            $detection->honeypotValue = $data['honeypot_value'];
        }
        if (isset($data['source'])) {
            $detection->source = $data['source'];
        }
        if (isset($data['threat_level'])) {
            $detection->threatLevel = $data['threat_level'];
        }
        if (isset($data['metadata'])) {
            $detection->metadata = (array) $data['metadata'];
        }
        if (isset($data['timestamp'])) {
            $detection->timestamp = (int) $data['timestamp'];
        }

        return $detection;
    }

    /**
     * Convert detection to API payload format
     *
     * @param string $organizationId The organization ID
     * @return array The API payload
     */
    public function toApiPayload(string $organizationId): array
    {
        $payload = [
            'aid' => $organizationId,
            'v' => 1, // Protocol version
            's' => $this->clientScore,
            'f' => $this->flags,
            'fp' => $this->fingerprint,
            'url' => $this->url ?? '',
            'ref' => $this->referer ?? '',
            'ts' => $this->timestamp ?? (int) (microtime(true) * 1000),
        ];

        if ($this->scannerId) {
            $payload['sid'] = $this->scannerId;
        }

        if ($this->aiBot) {
            $payload['ai'] = $this->aiBot;
        }

        if ($this->honeypotValue) {
            $payload['hp'] = $this->honeypotValue;
        }

        // Include IP address and user agent for server-side detections
        // These are essential for the ingest service to properly identify the client
        if ($this->ipAddress) {
            $payload['ip'] = $this->ipAddress;
        }

        if ($this->userAgent) {
            $payload['ua'] = $this->userAgent;
        }

        if ($this->source) {
            $payload['source'] = $this->source;
        }

        // Include metadata (MITRE tactic info, etc.)
        if (!empty($this->metadata)) {
            $payload['metadata'] = $this->metadata;
        }

        return $payload;
    }

    /**
     * Convert detection to array
     *
     * @return array
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'scanner_id' => $this->scannerId,
            'ip_address' => $this->ipAddress,
            'user_agent' => $this->userAgent,
            'referer' => $this->referer,
            'url' => $this->url,
            'client_score' => $this->clientScore,
            'flags' => $this->flags,
            'fingerprint' => $this->fingerprint,
            'ai_bot' => $this->aiBot,
            'honeypot_value' => $this->honeypotValue,
            'source' => $this->source,
            'threat_level' => $this->threatLevel,
            'metadata' => $this->metadata,
            'timestamp' => $this->timestamp,
        ];
    }

    // Getters and Setters

    public function getId(): ?string
    {
        return $this->id;
    }

    public function setId(?string $id): self
    {
        $this->id = $id;
        return $this;
    }

    public function getScannerId(): ?string
    {
        return $this->scannerId;
    }

    public function setScannerId(?string $scannerId): self
    {
        $this->scannerId = $scannerId;
        return $this;
    }

    public function getIpAddress(): ?string
    {
        return $this->ipAddress;
    }

    public function setIpAddress(?string $ipAddress): self
    {
        $this->ipAddress = $ipAddress;
        return $this;
    }

    public function getUserAgent(): ?string
    {
        return $this->userAgent;
    }

    public function setUserAgent(?string $userAgent): self
    {
        $this->userAgent = $userAgent;
        return $this;
    }

    public function getReferer(): ?string
    {
        return $this->referer;
    }

    public function setReferer(?string $referer): self
    {
        $this->referer = $referer;
        return $this;
    }

    public function getUrl(): ?string
    {
        return $this->url;
    }

    public function setUrl(?string $url): self
    {
        $this->url = $url;
        return $this;
    }

    public function getClientScore(): int
    {
        return $this->clientScore;
    }

    public function setClientScore(int $clientScore): self
    {
        $this->clientScore = max(0, min(100, $clientScore));
        return $this;
    }

    public function getFlags(): array
    {
        return $this->flags;
    }

    public function setFlags(array $flags): self
    {
        $this->flags = $flags;
        return $this;
    }

    public function addFlag(string $flag): self
    {
        if (!in_array($flag, $this->flags, true)) {
            $this->flags[] = $flag;
        }
        return $this;
    }

    public function getFingerprint(): array
    {
        return $this->fingerprint;
    }

    public function setFingerprint(array $fingerprint): self
    {
        $this->fingerprint = $fingerprint;
        return $this;
    }

    public function getAiBot(): ?string
    {
        return $this->aiBot;
    }

    public function setAiBot(?string $aiBot): self
    {
        $this->aiBot = $aiBot;
        return $this;
    }

    public function getHoneypotValue(): ?string
    {
        return $this->honeypotValue;
    }

    public function setHoneypotValue(?string $honeypotValue): self
    {
        $this->honeypotValue = $honeypotValue;
        return $this;
    }

    public function getSource(): ?string
    {
        return $this->source;
    }

    public function setSource(?string $source): self
    {
        $this->source = $source;
        return $this;
    }

    public function getThreatLevel(): ?string
    {
        return $this->threatLevel;
    }

    public function setThreatLevel(?string $threatLevel): self
    {
        $this->threatLevel = $threatLevel;
        return $this;
    }

    public function getMetadata(): array
    {
        return $this->metadata;
    }

    public function setMetadata(array $metadata): self
    {
        $this->metadata = $metadata;
        return $this;
    }

    public function addMetadata(string $key, $value): self
    {
        $this->metadata[$key] = $value;
        return $this;
    }

    public function getTimestamp(): ?int
    {
        return $this->timestamp;
    }

    public function setTimestamp(?int $timestamp): self
    {
        $this->timestamp = $timestamp;
        return $this;
    }
}
