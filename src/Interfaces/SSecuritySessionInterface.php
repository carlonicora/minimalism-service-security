<?php
namespace carlonicora\minimalism\services\security\Interfaces;

use Exception;

interface SSecuritySessionInterface {
    /**
     * @param string $publicKey
     * @param string $clientId
     * @return string
     * @throws Exception
     */
    public function getPrivateKey(string $publicKey, string $clientId): string;
}