<?php
namespace carlonicora\minimalism\services\security;

use carlonicora\minimalism\core\services\abstracts\abstractService;
use carlonicora\minimalism\core\services\factories\servicesFactory;
use carlonicora\minimalism\core\services\interfaces\serviceConfigurationsInterface;
use carlonicora\minimalism\services\logger\traits\logger;
use carlonicora\minimalism\services\security\configurations\securityConfigurations;
use carlonicora\minimalism\services\security\errors\errors;
use carlonicora\minimalism\services\security\exceptions\sessionExpiredException;
use carlonicora\minimalism\services\security\exceptions\unauthorisedException;
use carlonicora\minimalism\services\security\interfaces\securityClientInterface;
use carlonicora\minimalism\services\security\interfaces\securitySessionInterface;
use Throwable;

class security extends abstractService {
    use logger;

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
        $this->loggerInitialise($services);
    }

    /**
     * @return string
     */
    public function getHttpHeaderSignature() : string {
        return $this->configData->httpHeaderSignature;
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
     */
    public function generateSignature($verb, $uri, $body, $clientId, $clientSecret, $publicKey, $privateKey, $time=null): ?string {
        $returnValue = null;

        if (empty($time)) {
            $time = time();
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
     * @throws unauthorisedException
     */
    public function validateSignature($signature, $verb, $uri, $body, securityClientInterface $client, securitySessionInterface $session): void {
        if (empty($signature)) {
            $message = 'Security violation: missing signature. URI: "'. $uri . ', verb: ' . $verb . ', body: ' . print_r($body, true);
            $this->loggerWriteError(errors::SIGNATURE_MISSED, $message, errors::LOGGER_SERVICE_NAME);

            throw new unauthorisedException(errors::SIGNATURE_MISSED);
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
            $message = 'Security violation: signature structure error. Signature length = ' . strlen($signature);
            $this->loggerWriteError(errors::SIGNATURE_INCORRECT_STRUCTURE, $message, errors::LOGGER_SERVICE_NAME);

            throw new unauthorisedException(errors::SIGNATURE_INCORRECT_STRUCTURE);
        }

        $timeNow = time();
        $timeDifference = $timeNow - $time;

        if ($timeDifference > 10 || $timeDifference < -10) {
            $message = 'Security violation: signature expired. Time difference: ' . $timeDifference;
            $this->loggerWriteError(errors::SIGNATURE_EXPIRED, $message, errors::LOGGER_SERVICE_NAME);

            throw new unauthorisedException(errors::SIGNATURE_EXPIRED);
        }

        try {
            $this->configData->clientSecret = $client->getSecret($this->configData->clientId);
        } catch (Throwable $e) {
            $message = 'Security violation: invalid client id "' . $this->configData->clientId . '"';
            $this->loggerWriteError(errors::INVALID_CLIENT, $message, errors::LOGGER_SERVICE_NAME, $e);

            throw new unauthorisedException(errors::INVALID_CLIENT, $e);
        }

        $this->configData->privateKey=null;

        $auth = null;
        if (!empty($this->configData->publicKey)){
            try {
                $this->configData->privateKey = $session->getPrivateKey($this->configData->publicKey, $this->configData->clientId);
            } catch (unauthorisedException | sessionExpiredException $exception) {
                throw $exception;
            } catch (Throwable $e) {
                $message = 'Security violation: Unknown error. Public key "' . $this->configData->publicKey . '". Client id "' . $this->configData->clientId . '"';
                $this->loggerWriteError(errors::SESSION_ERROR_UNKNOWN, $message, errors::LOGGER_SERVICE_NAME, $e);

                throw new unauthorisedException(errors::SESSION_ERROR_UNKNOWN, $e);
            }
        }

        if ($verb === 'GET'){
            $body = null;
        }

        $validatedSignature = $this->generateSignature($verb, $uri, $body, $this->configData->clientId, $this->configData->clientSecret, $this->configData->publicKey, $this->configData->privateKey, $time);

        if ($validatedSignature !== $signature) {
            $message = 'Security violation: signatures mismatch. Real signture "' . $validatedSignature . '". Received signature "' . $signature . '"';
            $this->loggerWriteError(errors::SIGNATURE_MISMATCH, $message, errors::LOGGER_SERVICE_NAME);

            throw new unauthorisedException(errors::SIGNATURE_MISMATCH);
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
            $message = 'Entropy error. Could not generate random bytes. ' . $exception->getMessage();
            $this->loggerWriteError(errors::ENTROPY_EXCEPTION, $message, errors::LOGGER_SERVICE_NAME, $exception);

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