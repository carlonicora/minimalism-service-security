<?php
namespace CarloNicora\Minimalism\Services\Security\Exceptions;

use Exception;
use Throwable;

class UnauthorisedException extends Exception
{
    /**
     * unauthorisedException constructor.
     * @param string $code
     * @param Throwable|null $previous
     */
    public function __construct(string $code, Throwable $previous = null) {
        parent::__construct('Unauthorised', $code, $previous);
    }
}