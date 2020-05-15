<?php
namespace CarloNicora\Minimalism\Services\Security\Configurations;

use CarloNicora\Minimalism\Core\Services\Abstracts\AbstractServiceConfigurations;
use CarloNicora\Minimalism\Core\Services\Factories\ServicesFactory;
use CarloNicora\Minimalism\Services\Security\Interfaces\SecurityClientInterface;
use CarloNicora\Minimalism\Services\Security\Interfaces\SecuritySessionInterface;

class SecurityConfigurations extends AbstractServiceConfigurations {
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

    /** @var SecurityClientInterface|null  */
    public ?SecurityClientInterface $securityClient=null;

    /** @var SecuritySessionInterface|null  */
    public ?SecuritySessionInterface $securitySession=null;

    /**
     * securityConfigurations constructor.
     */
    public function __construct()
    {
        $this->httpHeaderSignature = getenv('MINIMALISM_SERVICE_SECURITY_HEADER_SIGNATURE') ?: 'Minimalism-Signature';
    }

    /**
     * @param ServicesFactory $services
     */
    public function setupSecurityInterfaces(ServicesFactory $services): void
    {

    }
}