<?php

declare(strict_types=1);

namespace WebDecoy\Rules;

use WebDecoy\Rules\Filter\Parser;
use WebDecoy\Rules\Filter\Evaluator;

/**
 * Filter Rule — a {@see RuleInterface} backed by the filter expression language.
 * Faithful PHP port of @webdecoy/node's filter-rule.ts.
 *
 * The expression is parsed at construction time so a syntax error fails fast
 * (surfaced by the admin UI on save) rather than throwing during request
 * evaluation. If the expression evaluates truthy for a request, the rule fires
 * with its configured action (default DENY).
 */
class FilterRule implements RuleInterface
{
    /** @var string */
    private $name;

    /** @var array<string,mixed> Parsed AST root. */
    private $ast;

    /** @var string DENY or THROTTLE. */
    private $action;

    /** @var bool */
    private $dryRun;

    /** @var string */
    private $expression;

    /**
     * @param array<string,mixed> $config {
     *     @type string $expression  Required. Filter expression source.
     *     @type string $action      DENY (default) or THROTTLE.
     *     @type bool   $dryRun      Record but don't block (default false).
     *     @type string $name        Optional explicit rule name.
     * }
     *
     * @throws \WebDecoy\Rules\Filter\FilterSyntaxException on a malformed expression.
     */
    public function __construct(array $config)
    {
        $this->expression = (string) ($config['expression'] ?? '');
        $this->action = ($config['action'] ?? RuleResult::DENY) === RuleResult::THROTTLE
            ? RuleResult::THROTTLE
            : RuleResult::DENY;
        $this->dryRun = !empty($config['dryRun']);
        $this->name = isset($config['name']) && $config['name'] !== ''
            ? (string) $config['name']
            : 'filter:' . substr($this->expression, 0, 50);

        // Parse now — fail fast on syntax errors.
        $this->ast = (new Parser($this->expression))->parse();
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function evaluate(RuleContext $context): RuleResult
    {
        $result = Evaluator::evaluate($this->ast, $context);

        if (Evaluator::isTruthy($result)) {
            return new RuleResult(
                $this->dryRun ? RuleResult::ALLOW : $this->action,
                $this->name,
                'Filter matched: ' . $this->expression,
                ['expression' => $this->expression, 'dryRun' => $this->dryRun]
            );
        }

        return RuleResult::allow($this->name);
    }

    /**
     * Whether this rule's expression references any `ip.*` field (so the caller
     * knows to fetch IP enrichment before evaluating). Mirrors node wiring
     * enrichment only when it's actually needed.
     */
    public function needsEnrichment(): bool
    {
        return strpos($this->expression, 'ip.') !== false;
    }
}
