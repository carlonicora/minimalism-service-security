<?php
namespace CarloNicora\Minimalism\Services\Security\Exceptions;

use RuntimeException;
use Throwable;

class SessionExpiredException extends RuntimeException
{
    /**
     * entityNotFoundException constructor.
     * @param string $code
     * @param Throwable|null $previous
     */
    public function __construct(string $code, Throwable $previous = null)
    {
        parent::__construct('Session expired', $code, $previous);
    }
}