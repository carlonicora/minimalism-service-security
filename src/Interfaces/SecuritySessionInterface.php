<?php
namespace CarloNicora\Minimalism\Services\Security\Interfaces;

use Exception;

interface SecuritySessionInterface
{
    /**
     * @param string $publicKey
     * @param string $clientId
     * @return string
     * @throws Exception
     */
    public function getPrivateKey(string $publicKey, string $clientId): string;
}