<?php
namespace carlonicora\minimalism\services\security\Factories;

use carlonicora\minimalism\core\services\exceptions\configurationException;
use carlonicora\minimalism\core\services\abstracts\abstractServiceFactory;
use carlonicora\minimalism\core\services\factories\servicesFactory;
use carlonicora\minimalism\services\security\Configurations\SSecurityConfigurations;
use carlonicora\minimalism\services\security\SSecurity;

class SServiceFactory extends abstractServiceFactory {
    /**
     * serviceFactory constructor.
     * @param servicesFactory $services
     * @throws configurationException
     */
    public function __construct(servicesFactory $services) {
        $this->configData = new SSecurityConfigurations();

        parent::__construct($services);
    }

    /**
     * @param servicesFactory $services
     * @return SSecurity|mixed
     */
    public function create(servicesFactory $services) {
        $this->configData->setupSecurityInterfaces($services);
        return new SSecurity($this->configData, $services);
    }
}