<?php
namespace carlonicora\minimalism\services\security\exceptions;

use RuntimeException;
use Throwable;

class sessionExpiredException extends RuntimeException {
    /**
     * entityNotFoundException constructor.
     * @param string $code
     * @param Throwable|null $previous
     */
    public function __construct(string $code, Throwable $previous = null) {
        parent::__construct('Session expired', $code, $previous);
    }
}