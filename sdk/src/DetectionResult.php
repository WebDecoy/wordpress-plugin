<?php

declare(strict_types=1);

namespace WebDecoy;

/**
 * Detection Result
 *
 * Represents the result of a bot detection analysis,
 * including the calculated score, threat level, and recommended action.
 */
class DetectionResult
{
    public const THREAT_MINIMAL = 'MINIMAL';
    public const THREAT_LOW = 'LOW';
    public const THREAT_MEDIUM = 'MEDIUM';
    public const THREAT_HIGH = 'HIGH';
    public const THREAT_CRITICAL = 'CRITICAL';

    public const ACTION_ALLOW = 'allow';
    public const ACTION_LOG = 'log';
    public const ACTION_CHALLENGE = 'challenge';
    public const ACTION_BLOCK = 'block';

    private int $score;
    private string $threatLevel;
    private string $recommendedAction;
    private array $flags;
    private ?string $botName = null;
    private ?string $botCategory = null;
    private bool $isGoodBot = false;
    private float $confidence = 0.0;
    private array $scoreBreakdown = [];
    private array $metadata = [];

    /**
     * Create a new detection result
     *
     * @param int $score Threat score 0-100
     * @param array $flags Detection flags
     */
    public function __construct(int $score = 0, array $flags = [])
    {
        $this->score = max(0, min(100, $score));
        $this->flags = $flags;
        $this->threatLevel = $this->calculateThreatLevel($this->score);
        $this->recommendedAction = $this->calculateRecommendedAction($this->score);
    }

    /**
     * Calculate threat level from score
     *
     * @param int $score
     * @return string
     */
    private function calculateThreatLevel(int $score): string
    {
        if ($score >= 80) {
            return self::THREAT_CRITICAL;
        }
        if ($score >= 60) {
            return self::THREAT_HIGH;
        }
        if ($score >= 40) {
            return self::THREAT_MEDIUM;
        }
        if ($score >= 20) {
            return self::THREAT_LOW;
        }
        return self::THREAT_MINIMAL;
    }

    /**
     * Calculate recommended action from score
     *
     * @param int $score
     * @return string
     */
    private function calculateRecommendedAction(int $score): string
    {
        if ($score >= 75) {
            return self::ACTION_BLOCK;
        }
        if ($score >= 50) {
            return self::ACTION_CHALLENGE;
        }
        if ($score >= 25) {
            return self::ACTION_LOG;
        }
        return self::ACTION_ALLOW;
    }

    /**
     * Check if the request should be blocked
     *
     * @param int $threshold Score threshold for blocking
     * @return bool
     */
    public function shouldBlock(int $threshold = 75): bool
    {
        // Never block good bots
        if ($this->isGoodBot) {
            return false;
        }

        return $this->score >= $threshold;
    }

    /**
     * Check if the request should be challenged
     *
     * @param int $threshold Score threshold for challenging
     * @return bool
     */
    public function shouldChallenge(int $threshold = 50): bool
    {
        if ($this->isGoodBot) {
            return false;
        }

        return $this->score >= $threshold && $this->score < 75;
    }

    /**
     * Check if the request should be logged only
     *
     * @return bool
     */
    public function shouldLog(): bool
    {
        return $this->score >= 20 && !$this->shouldBlock() && !$this->shouldChallenge();
    }

    /**
     * Check if the request appears legitimate
     *
     * @return bool
     */
    public function isLegitimate(): bool
    {
        return $this->score < 20 || $this->isGoodBot;
    }

    /**
     * Convert to array
     *
     * @return array
     */
    public function toArray(): array
    {
        return [
            'score' => $this->score,
            'threat_level' => $this->threatLevel,
            'recommended_action' => $this->recommendedAction,
            'flags' => $this->flags,
            'bot_name' => $this->botName,
            'bot_category' => $this->botCategory,
            'is_good_bot' => $this->isGoodBot,
            'confidence' => $this->confidence,
            'score_breakdown' => $this->scoreBreakdown,
            'metadata' => $this->metadata,
        ];
    }

    // Getters and Setters

    public function getScore(): int
    {
        return $this->score;
    }

    public function setScore(int $score): self
    {
        $this->score = max(0, min(100, $score));
        $this->threatLevel = $this->calculateThreatLevel($this->score);
        $this->recommendedAction = $this->calculateRecommendedAction($this->score);
        return $this;
    }

    public function getThreatLevel(): string
    {
        return $this->threatLevel;
    }

    public function getRecommendedAction(): string
    {
        return $this->recommendedAction;
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

    public function hasFlag(string $flag): bool
    {
        return in_array($flag, $this->flags, true);
    }

    public function getBotName(): ?string
    {
        return $this->botName;
    }

    public function setBotName(?string $botName): self
    {
        $this->botName = $botName;
        return $this;
    }

    public function getBotCategory(): ?string
    {
        return $this->botCategory;
    }

    public function setBotCategory(?string $botCategory): self
    {
        $this->botCategory = $botCategory;
        return $this;
    }

    public function isGoodBot(): bool
    {
        return $this->isGoodBot;
    }

    public function setIsGoodBot(bool $isGoodBot): self
    {
        $this->isGoodBot = $isGoodBot;
        return $this;
    }

    public function getConfidence(): float
    {
        return $this->confidence;
    }

    public function setConfidence(float $confidence): self
    {
        $this->confidence = max(0.0, min(1.0, $confidence));
        return $this;
    }

    public function getScoreBreakdown(): array
    {
        return $this->scoreBreakdown;
    }

    public function setScoreBreakdown(array $scoreBreakdown): self
    {
        $this->scoreBreakdown = $scoreBreakdown;
        return $this;
    }

    public function addScoreComponent(string $component, int $points): self
    {
        $this->scoreBreakdown[$component] = $points;
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
}
