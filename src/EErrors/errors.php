<?php
namespace carlonicora\minimalism\services\security\EErrors;

use carlonicora\minimalism\services\logger\abstracts\abstractErrors;

class errors extends abstractErrors {
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
    public const SESSION_EXPIRED = 7;
    /** @var int */
    public const SESSION_NOT_FOUND = 8;
    /** @var int */
    public const SESSION_ERROR_UNKNOWN = 9;

}