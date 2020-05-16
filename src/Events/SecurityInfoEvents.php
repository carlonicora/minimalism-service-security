<?php
namespace CarloNicora\Minimalism\Services\Security\Events;

use CarloNicora\Minimalism\Services\Logger\LogMessages\InfoLogMessage;

class SecurityInfoEvents extends InfoLogMessage
{
    /** @var string  */
    protected string $serviceName = 'security';
}