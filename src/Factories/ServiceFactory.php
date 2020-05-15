<?php
namespace CarloNicora\Minimalism\Services\Security\Factories;

use CarloNicora\Minimalism\Core\Services\Exceptions\ConfigurationException;
use CarloNicora\Minimalism\Core\Services\Abstracts\AbstractServiceFactory;
use CarloNicora\Minimalism\Core\Services\Factories\ServicesFactory;
use CarloNicora\Minimalism\Services\Security\Configurations\SecurityConfigurations;
use CarloNicora\Minimalism\Services\Security\Security;

class ServiceFactory extends AbstractServiceFactory
{
    /**
     * serviceFactory constructor.
     * @param ServicesFactory $services
     * @throws configurationException
     */
    public function __construct(ServicesFactory $services)
    {
        $this->configData = new SecurityConfigurations();

        parent::__construct($services);
    }

    /**
     * @param ServicesFactory $services
     * @return Security|mixed
     */
    public function create(ServicesFactory $services)
    {
        $this->configData->setupSecurityInterfaces($services);
        return new Security($this->configData, $services);
    }
}