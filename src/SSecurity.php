<?php
namespace carlonicora\minimalism\services\security;

use carlonicora\minimalism\core\services\abstracts\abstractService;
use carlonicora\minimalism\core\services\factories\servicesFactory;
use carlonicora\minimalism\core\services\interfaces\serviceConfigurationsInterface;
use carlonicora\minimalism\modules\jsonapi\api\exceptions\entityNotFoundException;
use carlonicora\minimalism\modules\jsonapi\api\exceptions\unauthorizedException;
use carlonicora\minimalism\services\logger\traits\logger;
use carlonicora\minimalism\services\security\Configurations\SSecurityConfigurations;
use carlonicora\minimalism\services\security\Errors\EErrors;
use carlonicora\minimalism\services\security\Exceptions\SSessionExpiredException;
use carlonicora\minimalism\services\security\Interfaces\SSecurityClientInterface;
use carlonicora\minimalism\services\security\Interfaces\SSecuritySessionInterface;
use Exception;

class SSecurity extends abstractService {
    use logger;

    /** @var SSecurityConfigurations  */
    private SSecurityConfigurations $configData;

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
     * @param SSecurityClientInterface $client
     * @param SSecuritySessionInterface $session
     * @throws unauthorizedException
     */
    public function validateSignature($signature, $verb, $uri, $body, SSecurityClientInterface $client, SSecuritySessionInterface $session): void {
        if (empty($signature)) {
            $message = 'Security violation: missing signature. URI: "'. $uri . ', verb: ' . $verb . ', body: ' . print_r($body, true);
            $this->loggerWriteError(EErrors::SIGNATURE_MISSED, $message, EErrors::LOGGER_SERVICE_NAME);

            throw new unauthorizedException(EErrors::SIGNATURE_MISSED);
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
            $this->loggerWriteError(EErrors::SIGNATURE_INCORRECT_STRUCTURE, $message, EErrors::LOGGER_SERVICE_NAME);

            throw new unauthorizedException(EErrors::SIGNATURE_INCORRECT_STRUCTURE);
        }

        $timeNow = time();
        $timeDifference = $timeNow - $time;

        if ($timeDifference > 10 || $timeDifference < -10) {
            $message = 'Security violation: signature expired. Time difference: ' . $timeDifference;
            $this->loggerWriteError(EErrors::SIGNATURE_EXPIRED, $message, EErrors::LOGGER_SERVICE_NAME);

            throw new unauthorizedException(EErrors::SIGNATURE_EXPIRED);
        }

        try {
            $this->configData->clientSecret = $client->getSecret($this->configData->clientId);
        } catch (Exception $e) {
            $message = 'Security violation: invalid client id "' . $this->configData->clientId . '"';
            $this->loggerWriteError(EErrors::SIGNATURE_MISSED, $message, EErrors::LOGGER_SERVICE_NAME, $e);

            throw new unauthorizedException(EErrors::INVALID_CLIENT, $e);
        }

        $this->configData->privateKey=null;

        $auth = null;
        if (!empty($this->configData->publicKey)){
            try {
                $this->configData->privateKey = $session->getPrivateKey($this->configData->publicKey, $this->configData->clientId);
            } catch (entityNotFoundException $notFoundException) {
                $message = 'Security violation: session not found. Public key "' . $this->configData->publicKey . '". Client id "' . $this->configData->clientId . '"';
                $this->loggerWriteError(EErrors::SESSION_NOT_FOUND, $message, EErrors::LOGGER_SERVICE_NAME, $notFoundException);

                throw new unauthorizedException(EErrors::SESSION_NOT_FOUND, $notFoundException);
            } catch (SSessionExpiredException $sessionExpiredException) {
                $message = 'Security violation: session expired. Public key "' . $this->configData->publicKey . '". Client id "' . $this->configData->clientId . '"';
                $this->loggerWriteError(EErrors::SESSION_EXPIRED, $message, EErrors::LOGGER_SERVICE_NAME, $sessionExpiredException);

                throw new unauthorizedException(EErrors::SESSION_EXPIRED, $sessionExpiredException);
            } catch (Exception $e) {
                $message = 'Security violation: Unknown error. Public key "' . $this->configData->publicKey . '". Client id "' . $this->configData->clientId . '"';
                $this->loggerWriteError(EErrors::SESSION_ERROR_UNKNOWN, $message, EErrors::LOGGER_SERVICE_NAME, $e);

                throw new unauthorizedException(EErrors::SESSION_ERROR_UNKNOWN, $e);
            }
        }

        if ($verb === 'GET'){
            $body = null;
        }

        $validatedSignature = $this->generateSignature($verb, $uri, $body, $this->configData->clientId, $this->configData->clientSecret, $this->configData->publicKey, $this->configData->privateKey, $time);

        if ($validatedSignature !== $signature) {
            $message = 'Security violation: signatures mismatch. Real signture "' . $validatedSignature . '". Received signature "' . $signature . '"';
            $this->loggerWriteError(EErrors::SIGNATURE_MISMATCH, $message, EErrors::LOGGER_SERVICE_NAME);

            throw new unauthorizedException(EErrors::SIGNATURE_MISMATCH);
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
     * @return SSecurityClientInterface
     */
    public function getSecurityClient(): SSecurityClientInterface {
        return $this->configData->securityClient;
    }

    /**
     * @return SSecuritySessionInterface
     */
    public function getSecuritySession(): SSecuritySessionInterface {
        return $this->configData->securitySession;
    }

    /**
     * @param SSecurityClientInterface $securityClient
     */
    public function setSecurityClient(SSecurityClientInterface $securityClient): void {
        $this->configData->securityClient = $securityClient;
    }

    /**
     * @param SSecuritySessionInterface $securitySession
     */
    public function setSecuritySession(SSecuritySessionInterface $securitySession): void {
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
        } catch (Exception $exception) {
            $message = 'Entropy error. Could not generate random bytes. ' . $exception->getMessage();
            $this->loggerWriteError(EErrors::ENTROPY_EXCEPTION, $message, EErrors::LOGGER_SERVICE_NAME, $exception);

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