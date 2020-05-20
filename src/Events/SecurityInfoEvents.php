<?php
namespace CarloNicora\Minimalism\Services\Security\Events;

use CarloNicora\Minimalism\Core\Events\Abstracts\AbstractInfoEvent;

class SecurityInfoEvents extends AbstractInfoEvent
{
    /** @var string  */
    protected string $serviceName = 'security';
}