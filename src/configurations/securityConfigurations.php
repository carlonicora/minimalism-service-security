<?php
namespace carlonicora\minimalism\services\security\CConfigurations;

use carlonicora\minimalism\core\services\abstracts\abstractServiceConfigurations;
use carlonicora\minimalism\core\services\factories\servicesFactory;
use carlonicora\minimalism\services\security\IInterfaces\securityClientInterface;
use carlonicora\minimalism\services\security\IInterfaces\securitySessionInterface;

class securityConfigurations extends abstractServiceConfigurations {
    /** @var string  */
    public string $httpHeaderSignature;

    /** @var string|null  */
    public ?string $clientId=null;

    /** @var string|null  */
    public ?string $clientSecret=null;

    /** @var string|null  */
    public ?string $publicKey=null;

    /** @var string|null  */
    public ?string $privateKey=null;

    /** @var securityClientInterface|null  */
    public ?securityClientInterface $securityClient=null;

    /** @var securitySessionInterface|null  */
    public ?securitySessionInterface $securitySession=null;

    /**
     * securityConfigurations constructor.
     */
    public function __construct() {
        $this->httpHeaderSignature = getenv('MINIMALISM_SERVICE_SECURITY_HEADER_SIGNATURE') ?: 'Minimalism-Signature';
    }

    /**
     * @param servicesFactory $services
     */
    public function setupSecurityInterfaces(servicesFactory $services): void {}
}