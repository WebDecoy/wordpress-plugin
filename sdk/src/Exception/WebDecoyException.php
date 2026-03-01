<?php

declare(strict_types=1);

namespace WebDecoy\Exception;

use Exception;

/**
 * WebDecoy Exception
 *
 * Base exception class for all WebDecoy SDK errors.
 */
class WebDecoyException extends Exception
{
    /**
     * Additional error context
     *
     * @var array
     */
    protected array $context = [];

    /**
     * Create a new WebDecoy exception
     *
     * @param string $message Error message
     * @param int $code Error code (HTTP status code for API errors)
     * @param Exception|null $previous Previous exception
     * @param array $context Additional error context
     */
    public function __construct(
        string $message = '',
        int $code = 0,
        ?Exception $previous = null,
        array $context = []
    ) {
        parent::__construct($message, $code, $previous);
        $this->context = $context;
    }

    /**
     * Get error context
     *
     * @return array
     */
    public function getContext(): array
    {
        return $this->context;
    }

    /**
     * Add context to the exception
     *
     * @param string $key Context key
     * @param mixed $value Context value
     * @return self
     */
    public function addContext(string $key, $value): self
    {
        $this->context[$key] = $value;
        return $this;
    }

    /**
     * Check if this is an API error
     *
     * @return bool
     */
    public function isApiError(): bool
    {
        return $this->code >= 400 && $this->code < 600;
    }

    /**
     * Check if this is an authentication error
     *
     * @return bool
     */
    public function isAuthError(): bool
    {
        return $this->code === 401 || $this->code === 403;
    }

    /**
     * Check if this is a rate limit error
     *
     * @return bool
     */
    public function isRateLimitError(): bool
    {
        return $this->code === 429;
    }

    /**
     * Check if this is a validation error
     *
     * @return bool
     */
    public function isValidationError(): bool
    {
        return $this->code === 400;
    }

    /**
     * Check if this is a server error
     *
     * @return bool
     */
    public function isServerError(): bool
    {
        return $this->code >= 500 && $this->code < 600;
    }

    /**
     * Check if the error is retryable
     *
     * @return bool
     */
    public function isRetryable(): bool
    {
        // Rate limit and server errors are typically retryable
        return $this->isRateLimitError() || $this->isServerError();
    }

    /**
     * Create exception from API response
     *
     * @param int $statusCode HTTP status code
     * @param array $response Decoded response body
     * @return self
     */
    public static function fromApiResponse(int $statusCode, array $response): self
    {
        $message = $response['error']['message']
            ?? $response['message']
            ?? 'Unknown API error';

        $context = [
            'status_code' => $statusCode,
            'response' => $response,
        ];

        if (isset($response['error']['code'])) {
            $context['error_code'] = $response['error']['code'];
        }

        return new self($message, $statusCode, null, $context);
    }

    /**
     * Create exception for connection failure
     *
     * @param string $url The URL that failed
     * @param string $error The error message
     * @return self
     */
    public static function connectionFailed(string $url, string $error): self
    {
        return new self(
            "Failed to connect to WebDecoy API: {$error}",
            0,
            null,
            ['url' => $url, 'error' => $error]
        );
    }

    /**
     * Create exception for invalid configuration
     *
     * @param string $message Configuration error message
     * @return self
     */
    public static function invalidConfiguration(string $message): self
    {
        return new self("Invalid configuration: {$message}", 0);
    }

    /**
     * Create exception for missing API key
     *
     * @return self
     */
    public static function missingApiKey(): self
    {
        return new self('API key is required', 0);
    }

    /**
     * Create exception for missing organization ID
     *
     * @return self
     */
    public static function missingOrganizationId(): self
    {
        return new self('Organization ID is required', 0);
    }

    /**
     * Convert to array for logging
     *
     * @return array
     */
    public function toArray(): array
    {
        return [
            'message' => $this->getMessage(),
            'code' => $this->getCode(),
            'context' => $this->context,
            'file' => $this->getFile(),
            'line' => $this->getLine(),
        ];
    }

    /**
     * String representation
     *
     * @return string
     */
    public function __toString(): string
    {
        $str = "WebDecoyException: [{$this->code}] {$this->message}";

        if (!empty($this->context)) {
            $str .= ' | Context: ' . json_encode($this->context);
        }

        return $str;
    }
}
