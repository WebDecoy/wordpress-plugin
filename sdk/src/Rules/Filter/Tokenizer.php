<?php

declare(strict_types=1);

namespace WebDecoy\Rules\Filter;

/**
 * Filter expression tokenizer — converts an expression string into a token
 * stream. Faithful PHP port of @webdecoy/node's filter/tokenizer.ts.
 *
 * Tokens are plain arrays: ['type' => <TokenType const>, 'value' => string,
 * 'position' => int].
 */
final class TokenType
{
    // Literals
    public const IDENT = 'IDENT';
    public const STRING = 'STRING';
    public const NUMBER = 'NUMBER';
    public const BOOL = 'BOOL';

    // Operators
    public const AND_ = 'AND';
    public const OR_ = 'OR';
    public const NOT_ = 'NOT';
    public const EQ = 'EQ';         // ==
    public const NEQ = 'NEQ';       // !=
    public const GT = 'GT';         // >
    public const GTE = 'GTE';       // >=
    public const LT = 'LT';         // <
    public const LTE = 'LTE';       // <=
    public const IN_ = 'IN';        // in
    public const MATCHES = 'MATCHES'; // matches

    // Punctuation
    public const DOT = 'DOT';
    public const LPAREN = 'LPAREN';
    public const RPAREN = 'RPAREN';
    public const LBRACKET = 'LBRACKET';
    public const RBRACKET = 'RBRACKET';
    public const COMMA = 'COMMA';

    // Special
    public const EOF = 'EOF';
}

final class Tokenizer
{
    /** @var array<string,string> */
    private const KEYWORDS = [
        'and' => TokenType::AND_,
        'or' => TokenType::OR_,
        'not' => TokenType::NOT_,
        'in' => TokenType::IN_,
        'matches' => TokenType::MATCHES,
        'true' => TokenType::BOOL,
        'false' => TokenType::BOOL,
    ];

    /** @var string */
    private $source;

    /** @var int */
    private $pos = 0;

    /** @var array<int,array<string,mixed>> */
    private $tokens = [];

    public function __construct(string $source)
    {
        $this->source = $source;
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    public function tokenize(): array
    {
        $len = strlen($this->source);

        while ($this->pos < $len) {
            $this->skipWhitespace();
            if ($this->pos >= $len) {
                break;
            }

            $ch = $this->source[$this->pos];

            if ($ch === '.') {
                $this->push(TokenType::DOT, '.');
                $this->pos++;
                continue;
            }
            if ($ch === '(') {
                $this->push(TokenType::LPAREN, '(');
                $this->pos++;
                continue;
            }
            if ($ch === ')') {
                $this->push(TokenType::RPAREN, ')');
                $this->pos++;
                continue;
            }
            if ($ch === '[') {
                $this->push(TokenType::LBRACKET, '[');
                $this->pos++;
                continue;
            }
            if ($ch === ']') {
                $this->push(TokenType::RBRACKET, ']');
                $this->pos++;
                continue;
            }
            if ($ch === ',') {
                $this->push(TokenType::COMMA, ',');
                $this->pos++;
                continue;
            }

            // Comparison operators
            if ($ch === '=' && $this->peek(1) === '=') {
                $this->push(TokenType::EQ, '==');
                $this->pos += 2;
                continue;
            }
            if ($ch === '!' && $this->peek(1) === '=') {
                $this->push(TokenType::NEQ, '!=');
                $this->pos += 2;
                continue;
            }
            if ($ch === '>' && $this->peek(1) === '=') {
                $this->push(TokenType::GTE, '>=');
                $this->pos += 2;
                continue;
            }
            if ($ch === '<' && $this->peek(1) === '=') {
                $this->push(TokenType::LTE, '<=');
                $this->pos += 2;
                continue;
            }
            if ($ch === '>') {
                $this->push(TokenType::GT, '>');
                $this->pos++;
                continue;
            }
            if ($ch === '<') {
                $this->push(TokenType::LT, '<');
                $this->pos++;
                continue;
            }

            // String literals
            if ($ch === '"' || $ch === "'") {
                $this->readString($ch);
                continue;
            }

            // Numbers
            if ($this->isDigit($ch) || ($ch === '-' && $this->isDigit($this->peek(1)))) {
                $this->readNumber();
                continue;
            }

            // Identifiers and keywords
            if ($this->isIdentStart($ch)) {
                $this->readIdent();
                continue;
            }

            throw new FilterSyntaxException("Unexpected character '{$ch}' at position {$this->pos}");
        }

        $this->tokens[] = ['type' => TokenType::EOF, 'value' => '', 'position' => $this->pos];
        return $this->tokens;
    }

    private function push(string $type, string $value): void
    {
        $this->tokens[] = ['type' => $type, 'value' => $value, 'position' => $this->pos];
    }

    private function peek(int $offset): string
    {
        $idx = $this->pos + $offset;
        return $idx < strlen($this->source) ? $this->source[$idx] : '';
    }

    private function skipWhitespace(): void
    {
        $len = strlen($this->source);
        while ($this->pos < $len && ctype_space($this->source[$this->pos])) {
            $this->pos++;
        }
    }

    private function readString(string $quote): void
    {
        $start = $this->pos;
        $this->pos++; // skip opening quote
        $value = '';
        $len = strlen($this->source);
        while ($this->pos < $len && $this->source[$this->pos] !== $quote) {
            if ($this->source[$this->pos] === '\\') {
                $this->pos++; // skip escape
            }
            if ($this->pos >= $len) {
                break;
            }
            $value .= $this->source[$this->pos];
            $this->pos++;
        }
        if ($this->pos >= $len) {
            throw new FilterSyntaxException("Unterminated string at position {$start}");
        }
        $this->pos++; // skip closing quote
        $this->tokens[] = ['type' => TokenType::STRING, 'value' => $value, 'position' => $start];
    }

    private function readNumber(): void
    {
        $start = $this->pos;
        $len = strlen($this->source);
        if ($this->source[$this->pos] === '-') {
            $this->pos++;
        }
        while ($this->pos < $len && $this->isDigit($this->source[$this->pos])) {
            $this->pos++;
        }
        if ($this->pos < $len && $this->source[$this->pos] === '.') {
            $this->pos++;
            while ($this->pos < $len && $this->isDigit($this->source[$this->pos])) {
                $this->pos++;
            }
        }
        $this->tokens[] = [
            'type' => TokenType::NUMBER,
            'value' => substr($this->source, $start, $this->pos - $start),
            'position' => $start,
        ];
    }

    private function readIdent(): void
    {
        $start = $this->pos;
        $len = strlen($this->source);
        while ($this->pos < $len && $this->isIdentPart($this->source[$this->pos])) {
            $this->pos++;
        }
        $value = substr($this->source, $start, $this->pos - $start);
        $lower = strtolower($value);
        if (isset(self::KEYWORDS[$lower])) {
            $this->tokens[] = ['type' => self::KEYWORDS[$lower], 'value' => $lower, 'position' => $start];
        } else {
            $this->tokens[] = ['type' => TokenType::IDENT, 'value' => $value, 'position' => $start];
        }
    }

    private function isDigit(string $ch): bool
    {
        return $ch >= '0' && $ch <= '9';
    }

    private function isIdentStart(string $ch): bool
    {
        return $ch === '_' || ctype_alpha($ch);
    }

    private function isIdentPart(string $ch): bool
    {
        return $ch === '_' || ctype_alnum($ch);
    }
}
