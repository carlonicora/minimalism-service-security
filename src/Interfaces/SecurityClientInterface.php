<?php
namespace CarloNicora\Minimalism\Services\Security\Interfaces;

use Exception;

interface SecurityClientInterface
{
    /**
     * @param string $clientId
     * @return string
     * @throws Exception
     */
    public function getSecret(string $clientId): string;
}