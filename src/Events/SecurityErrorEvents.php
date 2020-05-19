<?php
namespace CarloNicora\Minimalism\Services\Security\Events;

use CarloNicora\Minimalism\Services\Logger\Interfaces\LogMessageInterface;
use CarloNicora\Minimalism\Services\Logger\LogMessages\ErrorLogMessage;
use Exception;

class SecurityErrorEvents extends ErrorLogMessage
{
    protected string $serviceName = 'security';

    public static function SIGNATURE_MISSED(string $uri, string $verb, string $body) : LogMessageInterface
    {
        return new self(2, 'Security violation: missing signature. URI: %s, verb: %s, body: %s', [$uri, $verb, $body]);
    }

    public static function SIGNATURE_INCORRECT_STRUCTURE(int $signatureLength) : LogMessageInterface
    {
        return new self(3, 'Security violation: signature structure error. Signature length: %d', [$signatureLength]);
    }

    public static function SIGNATURE_EXPIRED(int $timeDifference) : LogMessageInterface
    {
        return new self(4, 'Security violation: signature expired. Time difference: %d', [$timeDifference]);
    }

    public static function INVALID_CLIENT(string $clientId, Exception $e) : LogMessageInterface
    {
        return new self(6, 'Security violation: invalid client id: %s', [$clientId], $e);
    }

    public static function SESSION_ERROR_UNKNOWN(string $clientId ,string $publicKey, Exception $e) : LogMessageInterface
    {
        return new self(7, 'Security violation: Unknown error. ClientId: %s PublicKey: %s', [$clientId, $publicKey], $e);
    }

    public static function SIGNATURE_MISMATCH(string $computedSignature, string $receivedSignature) : LogMessageInterface
    {
        return new self(5, 'Security violation: signatures mismatch. Computed signture: %s. Received signature: %s', [$computedSignature, $receivedSignature]);
    }

    public static function ENTROPY_EXCEPTION(string $exceptionMessage, Exception $e) : LogMessageInterface
    {
        return new self(1, 'Entropy error. Could not generate random bytes. %s', [$exceptionMessage], $e);
    }
}