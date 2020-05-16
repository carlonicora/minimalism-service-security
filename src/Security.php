<?php
namespace CarloNicora\Minimalism\Services\Security;

use CarloNicora\Minimalism\Core\Services\Abstracts\AbstractService;
use CarloNicora\Minimalism\Core\Services\Factories\ServicesFactory;
use CarloNicora\Minimalism\Core\Services\Interfaces\ServiceConfigurationsInterface;
use CarloNicora\Minimalism\Services\Security\Configurations\SecurityConfigurations;
use CarloNicora\Minimalism\Services\Security\Events\SecurityErrorEvents;
use CarloNicora\Minimalism\Services\Security\Exceptions\UnauthorisedException;
use CarloNicora\Minimalism\Services\Security\Interfaces\SecurityClientInterface;
use CarloNicora\Minimalism\Services\Security\Interfaces\SecuritySessionInterface;
use JsonException;
use Throwable;

class Security extends AbstractService {
    /** @var securityConfigurations  */
    private securityConfigurations $configData;

    /**
     * abstractApiCaller constructor.
     * @param serviceConfigurationsInterface $configData
     * @param servicesFactory $services
     */
    public function __construct(serviceConfigurationsInterface $configData, servicesFactory $services) {
        parent::__construct($configData, $services);

        /** @noinspection PhpFieldAssignmentTypeMismatchInspection */
        $this->configData = $configData;
    }

    /**
     * @return string
     */
    public function getHttpHeaderSignature() : string {
        return $this->configData->httpHeaderSignature;
    }

    /**
     * @return int
     */
    public function getCurrentTime() : int
    {
        return time();
    }

    /**
     * @param $verb
     * @param $uri
     * @param $body
     * @param $clientId
     * @param $clientSecret
     * @param $publicKey
     * @param $privateKey
     * @param null $time
     * @return string|null
     * @throws JsonException
     */
    public function generateSignature($verb, $uri, $body, $clientId, $clientSecret, $publicKey, $privateKey, $time=null): ?string {
        $returnValue = null;

        if (empty($time)) {
            $time = $this->getCurrentTime();
        }

        $strings = array($verb, $uri, $time);
        if (isset($body) && count($body)) {
            $body_json = json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES, 512);
            $strings[] = md5($body_json);
        }
        if (!empty($privateKey)) {
            $strings[] = $privateKey;
        }

        $checksum = hash_hmac('SHA256', implode("\n", $strings), $clientSecret);

        $sessionPublicKey = empty($publicKey) ? '' : $publicKey;
        $returnValue = $clientId . $sessionPublicKey . $time . $checksum;

        return $returnValue;
    }

    /**
     * @param $signature
     * @param $verb
     * @param $uri
     * @param $body
     * @param securityClientInterface $client
     * @param securitySessionInterface $session
     * @throws JsonException
     * @throws Throwable
     */
    public function validateSignature($signature, $verb, $uri, $body, securityClientInterface $client, securitySessionInterface $session): void {
        if (empty($signature)) {
            $this->services->logger()->error()
                ->log(SecurityErrorEvents::SIGNATURE_MISSED($uri, $verb, json_encode($body, JSON_THROW_ON_ERROR)))
                ->throw(UnauthorisedException::class, 'Unauthorised');
        }

        $this->configData->clientId = '';
        $this->configData->publicKey = '';
        $time = null;

        if (strlen($signature) === 202){
            $this->configData->clientId = substr($signature, 0, 64);
            $this->configData->publicKey = substr($signature, 64, 64);
            $time = substr($signature, 128, 10);
        } elseif (strlen($signature) === 138){
            $this->configData->clientId = substr($signature, 0, 64);
            $time = substr($signature, 64, 10);
        } else {
            $this->services->logger()->error()
                ->log(SecurityErrorEvents::SIGNATURE_INCORRECT_STRUCTURE(strlen($signature)))
                ->throw(UnauthorisedException::class, 'Unathorised');
        }

        $timeNow = time();
        $timeDifference = $timeNow - $time;

        if ($timeDifference > 10 || $timeDifference < -10) {
            $this->services->logger()->error()
                ->log(SecurityErrorEvents::SIGNATURE_EXPIRED($timeDifference))
                ->throw(UnauthorisedException::class, 'Unathorised');
        }

        try {
            $this->configData->clientSecret = $client->getSecret($this->configData->clientId);
        } catch (Throwable $e) {
            $this->services->logger()->error()
                ->log(SecurityErrorEvents::INVALID_CLIENT($this->configData->clientId, $e))
                ->throw(UnauthorisedException::class, 'Unathorised');
        }

        $this->configData->privateKey=null;

        $auth = null;
        if (!empty($this->configData->publicKey)){
            try {
                $this->configData->privateKey = $session->getPrivateKey($this->configData->publicKey, $this->configData->clientId);
            } catch (Throwable $e) {
                $this->services->logger()->error()
                    ->log(SecurityErrorEvents::SESSION_ERROR_UNKNOWN($this->configData->clientId, $this->configData->publicKey, $e))
                    ->throw(UnauthorisedException::class, 'Unathorised');
            }
        }

        if ($verb === 'GET'){
            $body = null;
        }

        $validatedSignature = $this->generateSignature($verb, $uri, $body, $this->configData->clientId, $this->configData->clientSecret, $this->configData->publicKey, $this->configData->privateKey, $time);

        if ($validatedSignature !== $signature) {
            $this->services->logger()->error()
                ->log(SecurityErrorEvents::SIGNATURE_MISMATCH($validatedSignature, $signature))
                ->throw(UnauthorisedException::class, 'Unathorised');
        }
    }

    /**
     * Encrypts a string in order to generate a password
     *
     * @param string $password
     * @return string
     */
    public function encryptPassword($password): string {
        return password_hash($password, PASSWORD_BCRYPT);
    }

    /**
     * Verifies if a password matches its hash
     *
     * @param string $password
     * @param string $hash
     * @return bool
     */
    public function decryptPassword($password, $hash): bool {
        $returnValue = false;

        if (password_verify($password, $hash)){
            $returnValue = true;
        }

        return $returnValue;
    }

    /**
     * Generates a pair of public and private keys
     *
     * @param $publicKey
     * @param $privateKey
     */
    public function generateApiKeys(&$publicKey, &$privateKey): void {
        $publicKey = $this->createEncryptedString(32);
        $privateKey = $this->createEncryptedString(64);
    }

    /**
     * @return securityClientInterface
     */
    public function getSecurityClient(): securityClientInterface {
        return $this->configData->securityClient;
    }

    /**
     * @return securitySessionInterface
     */
    public function getSecuritySession(): securitySessionInterface {
        return $this->configData->securitySession;
    }

    /**
     * @param securityClientInterface $securityClient
     */
    public function setSecurityClient(securityClientInterface $securityClient): void {
        $this->configData->securityClient = $securityClient;
    }

    /**
     * @param securitySessionInterface $securitySession
     */
    public function setSecuritySession(securitySessionInterface $securitySession): void {
        $this->configData->securitySession = $securitySession;
    }

    /**
     * @return string|null
     */
    public function getClientId(): ?string {
        return $this->configData->clientId;
    }

    /**
     * @return string|null
     */
    public function getClientSecret(): ?string {
        return $this->configData->clientSecret;
    }

    /**
     * @return string|null
     */
    public function getPublicKey(): ?string {
        return $this->configData->publicKey;
    }

    /**
     * @return string|null
     */
    public function getPrivateKey(): ?string {
        return $this->configData->privateKey;
    }

    /**
     * @param string|null $clientId
     */
    public function setClientId(?string $clientId): void {
        $this->configData->clientId = $clientId;
    }

    /**
     * @param string|null $clientSecret
     */
    public function setClientSecret(?string $clientSecret): void {
        $this->configData->clientSecret = $clientSecret;
    }

    /**
     * @param string|null $publicKey
     */
    public function setPublicKey(?string $publicKey): void {
        $this->configData->publicKey = $publicKey;
    }

    /**
     * @param string|null $privateKey
     */
    public function setPrivateKey(?string $privateKey): void {
        $this->configData->privateKey = $privateKey;
    }

    /**
     *
     */
    public function destroyStatics() : void {
        $this->configData->publicKey = null;
        $this->configData->privateKey = null;
        $this->configData->clientSecret = null;
        $this->configData->clientId = null;
    }

    /**
     * @param int $bytes
     * @return string
     */
    public function createEncryptedString(int $bytes): string {
        try {
            $result = random_bytes($bytes);
        } catch (Throwable $exception) {
            $this->services->logger()->error()
                ->log(SecurityErrorEvents::ENTROPY_EXCEPTION($exception->getMessage(), $exception));

            $result = $this->randomString($bytes);
        }

        return bin2hex($result);
    }

    /**
     * @param int $length
     * @return string
     */
    private function randomString(int $length): string {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            /** @noinspection RandomApiMigrationInspection */
            $randomString .= $characters[mt_rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }
}