<?php
namespace carlonicora\minimalism\services\security\Interfaces;

use Exception;

interface SSecurityClientInterface {
    /**
     * @param string $clientId
     * @return string
     * @throws Exception
     */
    public function getSecret(string $clientId): string;
}