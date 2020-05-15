<?php
namespace CarloNicora\Minimalism\Services\Security\Errors;

use carlonicora\minimalism\Services\logger\Abstracts\AbstractErrors;

class Errors extends AbstractErrors
{
    /** @var string  */
    public const LOGGER_SERVICE_NAME = 'minimalism-service-security';

    /** @var int */
    public const ENTROPY_EXCEPTION = 1;
    /** @var int */
    public const SIGNATURE_MISSED = 2;
    /** @var int */
    public const SIGNATURE_INCORRECT_STRUCTURE = 3;
    /** @var int */
    public const SIGNATURE_EXPIRED = 4;
    /** @var int */
    public const SIGNATURE_MISMATCH = 5;
    /** @var int */
    public const INVALID_CLIENT = 6;
    /** @var int */
    public const SESSION_ERROR_UNKNOWN = 7;

}