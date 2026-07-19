<?php

declare(strict_types=1);

namespace WebDecoy\Rules\Filter;

/**
 * Thrown when a filter expression fails to tokenize or parse. Callers parse at
 * rule-construction time so a bad expression fails fast (and the admin UI can
 * surface the error) rather than throwing during request evaluation.
 */
class FilterSyntaxException extends \Exception
{
}
