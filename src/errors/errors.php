<?php
namespace carlonicora\minimalism\services\security\errors;

use carlonicora\minimalism\services\logger\abstracts\abstractErrors;

class errors extends abstractErrors {
    /** @var string  */
    public const LOGGER_SERVICE_NAME = 'minimalism-services-security';

    /** @var int  */
    public const ENTROPY_EXCEPTION = 1;

}