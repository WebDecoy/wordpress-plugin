<?php

declare(strict_types=1);

namespace WebDecoy\Rules\Filter;

/**
 * Filter expression parser — recursive-descent, producing an AST of associative
 * arrays. Faithful PHP port of @webdecoy/node's filter/parser.ts.
 *
 * AST node shapes (matching node's discriminated union via a 'kind' key):
 *   ['kind'=>'bool',   'value'=>bool]
 *   ['kind'=>'number', 'value'=>float]
 *   ['kind'=>'string', 'value'=>string]
 *   ['kind'=>'array',  'elements'=>ASTNode[]]
 *   ['kind'=>'property','path'=>string[]]
 *   ['kind'=>'call',   'object'=>string[], 'method'=>string, 'args'=>ASTNode[]]
 *   ['kind'=>'binary', 'op'=>string, 'left'=>ASTNode, 'right'=>ASTNode]
 *   ['kind'=>'unary',  'op'=>string, 'operand'=>ASTNode]
 *
 * Grammar:
 *   expression → or_expr
 *   or_expr    → and_expr ( "or" and_expr )*
 *   and_expr   → unary ( "and" unary )*
 *   unary      → "not" unary | comparison
 *   comparison → primary ( (== | != | > | >= | < | <= | in | not in | matches) primary )?
 *   primary    → BOOL | NUMBER | STRING | property | array | "(" expression ")"
 *   property   → IDENT ( "." IDENT )* ( "(" STRING ")" )?
 *   array      → "[" ( primary ( "," primary )* )? "]"
 */
final class Parser
{
    /** @var array<int,array<string,mixed>> */
    private $tokens;

    /** @var int */
    private $pos = 0;

    public function __construct(string $source)
    {
        $this->tokens = (new Tokenizer($source))->tokenize();
    }

    /**
     * @return array<string,mixed> AST root
     */
    public function parse(): array
    {
        $ast = $this->orExpr();
        $this->expect(TokenType::EOF, 'Expected end of expression');
        return $ast;
    }

    /**
     * @return array<string,mixed>
     */
    private function orExpr(): array
    {
        $left = $this->andExpr();
        while ($this->match(TokenType::OR_)) {
            $right = $this->andExpr();
            $left = ['kind' => 'binary', 'op' => 'or', 'left' => $left, 'right' => $right];
        }
        return $left;
    }

    /**
     * @return array<string,mixed>
     */
    private function andExpr(): array
    {
        $left = $this->unary();
        while ($this->match(TokenType::AND_)) {
            $right = $this->unary();
            $left = ['kind' => 'binary', 'op' => 'and', 'left' => $left, 'right' => $right];
        }
        return $left;
    }

    /**
     * @return array<string,mixed>
     */
    private function unary(): array
    {
        if ($this->match(TokenType::NOT_)) {
            // "not in" is handled in comparison — backtrack if we see IN next.
            if ($this->check(TokenType::IN_)) {
                $this->pos--;
                return $this->comparison();
            }
            $operand = $this->unary();
            return ['kind' => 'unary', 'op' => 'not', 'operand' => $operand];
        }
        return $this->comparison();
    }

    /**
     * @return array<string,mixed>
     */
    private function comparison(): array
    {
        $left = $this->primary();

        if ($this->match(TokenType::EQ)) {
            return ['kind' => 'binary', 'op' => '==', 'left' => $left, 'right' => $this->primary()];
        }
        if ($this->match(TokenType::NEQ)) {
            return ['kind' => 'binary', 'op' => '!=', 'left' => $left, 'right' => $this->primary()];
        }
        if ($this->match(TokenType::GT)) {
            return ['kind' => 'binary', 'op' => '>', 'left' => $left, 'right' => $this->primary()];
        }
        if ($this->match(TokenType::GTE)) {
            return ['kind' => 'binary', 'op' => '>=', 'left' => $left, 'right' => $this->primary()];
        }
        if ($this->match(TokenType::LT)) {
            return ['kind' => 'binary', 'op' => '<', 'left' => $left, 'right' => $this->primary()];
        }
        if ($this->match(TokenType::LTE)) {
            return ['kind' => 'binary', 'op' => '<=', 'left' => $left, 'right' => $this->primary()];
        }
        if ($this->match(TokenType::IN_)) {
            return ['kind' => 'binary', 'op' => 'in', 'left' => $left, 'right' => $this->primary()];
        }
        if ($this->match(TokenType::MATCHES)) {
            return ['kind' => 'binary', 'op' => 'matches', 'left' => $left, 'right' => $this->primary()];
        }

        // "not in"
        if ($this->check(TokenType::NOT_) && $this->checkAhead(TokenType::IN_)) {
            $this->advance(); // 'not'
            $this->advance(); // 'in'
            return ['kind' => 'binary', 'op' => 'not in', 'left' => $left, 'right' => $this->primary()];
        }

        return $left;
    }

    /**
     * @return array<string,mixed>
     */
    private function primary(): array
    {
        if ($this->check(TokenType::BOOL)) {
            $token = $this->advance();
            return ['kind' => 'bool', 'value' => $token['value'] === 'true'];
        }

        if ($this->check(TokenType::NUMBER)) {
            $token = $this->advance();
            return ['kind' => 'number', 'value' => (float) $token['value']];
        }

        if ($this->check(TokenType::STRING)) {
            $token = $this->advance();
            return ['kind' => 'string', 'value' => $token['value']];
        }

        if ($this->match(TokenType::LBRACKET)) {
            $elements = [];
            if (!$this->check(TokenType::RBRACKET)) {
                $elements[] = $this->primary();
                while ($this->match(TokenType::COMMA)) {
                    $elements[] = $this->primary();
                }
            }
            $this->expect(TokenType::RBRACKET, 'Expected "]"');
            return ['kind' => 'array', 'elements' => $elements];
        }

        if ($this->match(TokenType::LPAREN)) {
            $expr = $this->orExpr();
            $this->expect(TokenType::RPAREN, 'Expected ")"');
            return $expr;
        }

        if ($this->check(TokenType::IDENT)) {
            $path = [$this->advance()['value']];
            while ($this->match(TokenType::DOT)) {
                if (!$this->check(TokenType::IDENT)) {
                    throw new FilterSyntaxException('Expected identifier after "." at position ' . $this->current()['position']);
                }
                $path[] = $this->advance()['value'];
            }

            // Function call: req.header("x-api-key")
            if ($this->match(TokenType::LPAREN)) {
                $method = array_pop($path);
                $args = [];
                if (!$this->check(TokenType::RPAREN)) {
                    $args[] = $this->primary();
                    while ($this->match(TokenType::COMMA)) {
                        $args[] = $this->primary();
                    }
                }
                $this->expect(TokenType::RPAREN, 'Expected ")"');
                return ['kind' => 'call', 'object' => $path, 'method' => $method, 'args' => $args];
            }

            return ['kind' => 'property', 'path' => $path];
        }

        throw new FilterSyntaxException('Unexpected token "' . $this->current()['value'] . '" at position ' . $this->current()['position']);
    }

    /**
     * @return array<string,mixed>
     */
    private function current(): array
    {
        return $this->tokens[$this->pos];
    }

    /**
     * @return array<string,mixed>
     */
    private function advance(): array
    {
        return $this->tokens[$this->pos++];
    }

    private function check(string $type): bool
    {
        return $this->current()['type'] === $type;
    }

    private function checkAhead(string $type): bool
    {
        return $this->pos + 1 < count($this->tokens) && $this->tokens[$this->pos + 1]['type'] === $type;
    }

    private function match(string $type): bool
    {
        if ($this->check($type)) {
            $this->advance();
            return true;
        }
        return false;
    }

    /**
     * @return array<string,mixed>
     */
    private function expect(string $type, string $message): array
    {
        if ($this->check($type)) {
            return $this->advance();
        }
        throw new FilterSyntaxException($message . ', got "' . $this->current()['value'] . '" at position ' . $this->current()['position']);
    }
}
