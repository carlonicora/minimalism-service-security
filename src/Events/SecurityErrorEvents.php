<?php
namespace CarloNicora\Minimalism\Services\Security\Events;

use CarloNicora\Minimalism\Core\Events\Abstracts\AbstractErrorEvent;
use CarloNicora\Minimalism\Core\Events\Interfaces\EventInterface;
use CarloNicora\Minimalism\Core\Modules\Interfaces\ResponseInterface;
use Exception;

class SecurityErrorEvents extends AbstractErrorEvent
{
    protected string $serviceName = 'security';

    public static function SIGNATURE_MISSED(string $uri, string $verb, string $body) : EventInterface
    {
        return new self(2, ResponseInterface::HTTP_STATUS_401, 'Security violation: missing signature. URI: %s, verb: %s, body: %s', [$uri, $verb, $body]);
    }

    public static function SIGNATURE_INCORRECT_STRUCTURE(int $signatureLength) : EventInterface
    {
        return new self(3, ResponseInterface::HTTP_STATUS_400, 'Security violation: signature structure error. Signature length: %d', [$signatureLength]);
    }

    public static function SIGNATURE_EXPIRED(int $timeDifference) : EventInterface
    {
        return new self(4, ResponseInterface::HTTP_STATUS_400, 'Security violation: signature expired. Time difference: %d', [$timeDifference]);
    }

    public static function INVALID_CLIENT(string $clientId, Exception $e) : EventInterface
    {
        return new self(6, ResponseInterface::HTTP_STATUS_400, 'Security violation: invalid client id: %s', [$clientId], $e);
    }

    public static function SESSION_ERROR_UNKNOWN(string $clientId ,string $publicKey, Exception $e) : EventInterface
    {
        return new self(7, ResponseInterface::HTTP_STATUS_400, 'Security violation: Unknown error. ClientId: %s PublicKey: %s', [$clientId, $publicKey], $e);
    }

    public static function SIGNATURE_MISMATCH(string $computedSignature, string $receivedSignature) : EventInterface
    {
        return new self(5, ResponseInterface::HTTP_STATUS_400, 'Security violation: signatures mismatch. Computed signture: %s. Received signature: %s', [$computedSignature, $receivedSignature]);
    }

    public static function ENTROPY_EXCEPTION(string $exceptionMessage, Exception $e) : EventInterface
    {
        return new self(1, ResponseInterface::HTTP_STATUS_400, 'Entropy error. Could not generate random bytes. %s', [$exceptionMessage], $e);
    }
}