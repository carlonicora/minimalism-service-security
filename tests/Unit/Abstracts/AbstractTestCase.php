<?php
namespace CarloNicora\Minimalism\Services\Security\Tests\Unit\Abstracts;

use CarloNicora\Minimalism\Core\Services\Factories\ServicesFactory;
use CarloNicora\Minimalism\Services\Security\Factories\ServiceFactory;
use CarloNicora\Minimalism\Services\Security\Security;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionException;

class AbstractTestCase extends TestCase
{
    /** @var ServicesFactory|null  */
    protected ?ServicesFactory $services=null;

    /** @var Security|null  */
    protected ?Security $security=null;

    /**
     *
     */
    public function setUp(): void
    {
        parent::setUp();

        $this->services = new ServicesFactory();
        $this->security = $this->services->loadService(ServiceFactory::class);
    }

    /**
     * @param $object
     * @param $parameterName
     * @return mixed|null
     */
    protected function getProperty($object, $parameterName)
    {
        try {
            $reflection = new ReflectionClass(get_class($object));
            $property = $reflection->getProperty($parameterName);
            $property->setAccessible(true);
            return $property->getValue($object);
        } catch (ReflectionException $e) {
            return null;
        }
    }

    /**
     * @param $object
     * @param $parameterName
     * @param $parameterValue
     */
    protected function setProperty($object, $parameterName, $parameterValue): void
    {
        try {
            $reflection = new ReflectionClass(get_class($object));
            $property = $reflection->getProperty($parameterName);
            $property->setAccessible(true);
            $property->setValue($object, $parameterValue);
        } catch (ReflectionException $e) {
        }
    }
}