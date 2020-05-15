<?php
namespace carlonicora\minimalism\services\security\Configurations;

use carlonicora\minimalism\core\services\abstracts\abstractServiceConfigurations;
use carlonicora\minimalism\core\services\factories\servicesFactory;
use carlonicora\minimalism\services\security\Interfaces\SSecurityClientInterface;
use carlonicora\minimalism\services\security\Interfaces\SSecuritySessionInterface;

class SSecurityConfigurations extends abstractServiceConfigurations {
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

    /** @var SSecurityClientInterface|null  */
    public ?SSecurityClientInterface $securityClient=null;

    /** @var SSecuritySessionInterface|null  */
    public ?SSecuritySessionInterface $securitySession=null;

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