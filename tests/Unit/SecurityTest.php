<?php
namespace CarloNicora\Minimalism\Services\Security\Tests\Unit;

use CarloNicora\Minimalism\Core\Services\Factories\ServicesFactory;
use CarloNicora\Minimalism\Services\Security\Events\SecurityErrorEvents;
use CarloNicora\Minimalism\Services\Security\Factories\ServiceFactory;
use CarloNicora\Minimalism\Services\Security\Interfaces\SecurityClientInterface;
use CarloNicora\Minimalism\Services\Security\Interfaces\SecuritySessionInterface;
use CarloNicora\Minimalism\Services\Security\Security;
use CarloNicora\Minimalism\Services\Security\Tests\Unit\Abstracts\AbstractTestCase;
use Exception;
use JsonException;
use PHPUnit\Framework\MockObject\MockObject;
use Throwable;

class SecurityTest extends AbstractTestCase
{
    private string $publicKey='1234567890123456789012345678901234567890123456789012345678901234';
    private string $privateKey='1234567890123456789012345678901234567890123456789012345678901234';
    private string $clientId='1234567890123456789012345678901234567890123456789012345678901234';
    private string $clientSecret='1234567890123456789012345678901234567890123456789012345678901234';

    public function testSecurityInitialisation() : void
    {
        $this->services = new ServicesFactory();
        $this->services->loadService(ServiceFactory::class);
        $this->assertEquals(1,1);

    }

    public function testDefaultHttpHeaders() : void
    {
        $this->assertEquals('Minimalism-Signature', $this->security->getHttpHeaderSignature());
    }

    public function testCustomHttpHeaders() : void
    {
        $this->security = null;
        $this->services = new ServicesFactory();
        if (false === getenv('MINIMALISM_SERVICE_SECURITY_HEADER_SIGNATURE')) {
            putenv("MINIMALISM_SERVICE_SECURITY_HEADER_SIGNATURE=X-Phlow");
        }
        if (!isset($_ENV['MINIMALISM_SERVICE_SECURITY_HEADER_SIGNATURE'])) {
            $_ENV['MINIMALISM_SERVICE_SECURITY_HEADER_SIGNATURE'] = 'X-Phlow';
        }
        $this->security = $this->services->loadService(ServiceFactory::class);
        $this->assertEquals('X-Phlow', $this->security->getHttpHeaderSignature());
    }

    public function testGetCurrentTime() : void
    {
        $this->assertEquals(time(), $this->security->getCurrentTime());
    }

    /**
     * @throws JsonException
     */
    public function testGenerateSignatureWithPrivateKey() : void
    {
        $signature = $this->security->generateSignature('GET', '/uri', ['parameter'=>'value'], $this->clientId, $this->clientSecret, $this->publicKey, $this->privateKey, 123456789);
        $this->assertEquals(
            '12345678901234567890123456789012345678901234567890123456789012341234567890123456789012345678901234567890123456789012345678901234123456789b6b4849d813b65d54785c915f198e923e623eae63ad4aad27609ab0278acb6da',
            $signature);
    }

    /**
     * @throws JsonException
     */
    public function testGenerateSignatureWithoutPrivateKey() : void
    {
        $signature = $this->security->generateSignature('GET', '/uri', ['parameter'=>'value'], $this->clientId, $this->clientSecret, '', '', 123456789);
        $this->assertEquals(
            '1234567890123456789012345678901234567890123456789012345678901234123456789a6cfebaa61430854abffa1c9e1c14a4aedce059c46c69bc559f7f4870c2a9e0c',
            $signature);
    }

    /**
     * @throws JsonException
     */
    public function testGenerateSignatureWithDefaultTime() : void
    {
        /** @var MockObject|Security $mock */
        $mock = $this->getMockBuilder(Security::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getCurrentTime'])
            ->getMock();

        $mock->expects($this->once())
            ->method('getCurrentTime')
            ->willReturn(123456789);

        $signature = $mock->generateSignature('GET', '/uri', ['parameter'=>'value'], $this->clientId, $this->clientSecret, '', '');
        $this->assertEquals(
            '1234567890123456789012345678901234567890123456789012345678901234123456789a6cfebaa61430854abffa1c9e1c14a4aedce059c46c69bc559f7f4870c2a9e0c',
            $signature);
    }

    /**
     * @throws JsonException
     * @throws Throwable
     */
    public function testFailToValidateSignatureNoSignature() : void
    {
        $this->expectExceptionCode(401);

        /** @var MockObject|SecurityClientInterface $securityClientInterface */
        $securityClientInterface = $this->getMockBuilder(SecurityClientInterface::class)->getMock();

        /** @var SecuritySessionInterface $securityClientInterface */
        $securitySessionInterface = $this->getMockBuilder(SecuritySessionInterface::class)->getMock();

        /** @noinspection PhpParamsInspection */
        $this->security->validateSignature('', 'GET', '/uri', ['parameter'=>'value'], $securityClientInterface, $securitySessionInterface);
    }

    /**
     * @throws JsonException
     * @throws Throwable
     */
    public function testFailToValidateSignatureInvalidSignatureLength() : void
    {
        $this->expectExceptionCode(400);

        /** @var MockObject|SecurityClientInterface $securityClientInterface */
        $securityClientInterface = $this->getMockBuilder(SecurityClientInterface::class)->getMock();

        /** @var MockObject|SecuritySessionInterface $securityClientInterface */
        $securitySessionInterface = $this->getMockBuilder(SecuritySessionInterface::class)->getMock();

        /** @noinspection PhpParamsInspection */
        $this->security->validateSignature('clientItpublicKey123456789fa35de2350e222033d607b0e834bb8cf97f1a324147abdf02a0451de87d482b1a', 'GET', '/uri', ['parameter'=>'value'], $securityClientInterface, $securitySessionInterface);
    }

    /**
     * @throws JsonException
     * @throws Throwable
     */
    public function testFailToValidateSignatureInvalidTime() : void
    {
        $signature = $this->security->generateSignature('GET', '/uri', ['parameter'=>'value'], $this->clientId, $this->clientSecret, $this->publicKey, $this->privateKey, 1234567890);

        /** @var MockObject|SecurityClientInterface $securityClientInterface */
        $securityClientInterface = $this->getMockBuilder(SecurityClientInterface::class)->getMock();

        /** @var MockObject|SecuritySessionInterface $securityClientInterface */
        $securitySessionInterface = $this->getMockBuilder(SecuritySessionInterface::class)->getMock();

        $this->expectExceptionCode(400);
        /** @noinspection PhpParamsInspection */
        $this->security->validateSignature($signature, 'GET', '/uri', ['parameter'=>'value'], $securityClientInterface, $securitySessionInterface);
    }

    /**
     * @throws JsonException
     * @throws Throwable
     */
    public function testFailToValidateSignatureInvalidTimeNoSessionKey() : void
    {
        $signature = $this->security->generateSignature('GET', '/uri', ['parameter'=>'value'], $this->clientId, $this->clientSecret, '', '', 1234567890);

        /** @var MockObject|SecurityClientInterface $securityClientInterface */
        $securityClientInterface = $this->getMockBuilder(SecurityClientInterface::class)->getMock();

        /** @var MockObject|SecuritySessionInterface $securityClientInterface */
        $securitySessionInterface = $this->getMockBuilder(SecuritySessionInterface::class)->getMock();

        $this->expectExceptionCode(400);
        /** @noinspection PhpParamsInspection */
        $this->security->validateSignature($signature, 'GET', '/uri', ['parameter'=>'value'], $securityClientInterface, $securitySessionInterface);
    }

    /**
     * @throws JsonException
     * @throws Throwable
     */
    public function testFailToValidateSignatureInvalidClient() : void
    {
        $signature = $this->security->generateSignature('GET', '/uri', ['parameter'=>'value'], $this->clientId, $this->clientSecret, '', '');

        /** @var MockObject|SecurityClientInterface $securityClientInterface */
        $securityClientInterface = $this->getMockBuilder(SecurityClientInterface::class)
            ->onlyMethods(['getSecret'])
            ->getMock();

        $securityClientInterface->method('getSecret')
            ->willThrowException(new Exception('pippo was here'));

        /** @var MockObject|SecuritySessionInterface $securityClientInterface */
        $securitySessionInterface = $this->getMockBuilder(SecuritySessionInterface::class)->getMock();

        $this->expectExceptionCode(400);
        /** @noinspection PhpParamsInspection */
        $this->security->validateSignature($signature, 'GET', '/uri', ['parameter'=>'value'], $securityClientInterface, $securitySessionInterface);
    }

    /**
     * @throws JsonException
     * @throws Throwable
     */
    public function testFailToValidateSignatureInvalidSession() : void
    {
        $signature = $this->security->generateSignature('GET', '/uri', ['parameter'=>'value'], $this->clientId, $this->clientSecret, $this->publicKey, $this->privateKey);

        /** @var MockObject|SecurityClientInterface $securityClientInterface */
        $securityClientInterface = $this->getMockBuilder(SecurityClientInterface::class)
            ->onlyMethods(['getSecret'])
            ->getMock();

        $securityClientInterface->method('getSecret')
            ->willReturn($this->clientSecret);

        /** @var MockObject|SecuritySessionInterface $securityClientInterface */
        $securitySessionInterface = $this->getMockBuilder(SecuritySessionInterface::class)
            ->onlyMethods(['getPrivateKey'])
            ->getMock();

        $securitySessionInterface->method('getPrivateKey')
            ->willThrowException(new Exception('pippo was here'));
        /**
        $securitySessionInterface->method('getPrivateKey')
        ->willReturn($this->privateKey);
         */

        $this->expectExceptionCode(400);
        /** @noinspection PhpParamsInspection */
        $this->security->validateSignature($signature, 'GET', '/uri', ['parameter'=>'value'], $securityClientInterface, $securitySessionInterface);
    }

    /**
     * @throws JsonException
     * @throws Throwable
     */
    public function testFailToValidateSignatureMismatch() : void
    {
        $signature = $this->security->generateSignature('GET', '/uri', ['parameter'=>'value'], $this->clientId, $this->clientSecret, $this->publicKey, $this->privateKey);

        /** @var MockObject|SecurityClientInterface $securityClientInterface */
        $securityClientInterface = $this->getMockBuilder(SecurityClientInterface::class)
            ->onlyMethods(['getSecret'])
            ->getMock();

        $securityClientInterface->method('getSecret')
            ->willReturn($this->clientSecret);

        /** @var MockObject|SecuritySessionInterface $securityClientInterface */
        $securitySessionInterface = $this->getMockBuilder(SecuritySessionInterface::class)
            ->onlyMethods(['getPrivateKey'])
            ->getMock();

        $securitySessionInterface->method('getPrivateKey')
            ->willReturn($this->privateKey);

        $this->expectExceptionCode(400);
        /** @noinspection PhpParamsInspection */
        $this->security->validateSignature('0' . substr($signature, 1), 'GET', '/uri', ['parameter'=>'value'], $securityClientInterface, $securitySessionInterface);
    }

    /**
     * @throws JsonException
     * @throws Throwable
     */
    public function testValidateSignature() : void
    {
        $signature = $this->security->generateSignature('GET', '/uri', null, $this->clientId, $this->clientSecret, $this->publicKey, $this->privateKey);

        /** @var MockObject|SecurityClientInterface $securityClientInterface */
        $securityClientInterface = $this->getMockBuilder(SecurityClientInterface::class)
            ->onlyMethods(['getSecret'])
            ->getMock();

        $securityClientInterface->method('getSecret')
            ->willReturn($this->clientSecret);

        /** @var MockObject|SecuritySessionInterface $securityClientInterface */
        $securitySessionInterface = $this->getMockBuilder(SecuritySessionInterface::class)
            ->onlyMethods(['getPrivateKey'])
            ->getMock();

        $securitySessionInterface->method('getPrivateKey')
            ->willReturn($this->privateKey);

        /** @noinspection PhpParamsInspection */
        $this->security->validateSignature($signature, 'GET', '/uri', null, $securityClientInterface, $securitySessionInterface);

        $this->assertEquals(400,400);
    }

    public function testDecryptPassword() : void
    {
        $password = $this->security->encryptPassword('carlo');
        $decryptedpassword = $this->security->decryptPassword('carlo', $password);
        $this->assertTrue($decryptedpassword);
    }

    public function testGenerateApiKeys() : void
    {
        $public = null;
        $private = null;

        $this->security->generateApiKeys($public, $private);

        $this->assertNotNull($public);
        $this->assertNotNull($private);

    }

    /**
     * @throws Exception
     */
    public function testGetSecuritySession() : void
    {
        $securitySessionInterface = $this->getMockBuilder(SecuritySessionInterface::class)
            ->onlyMethods(['getPrivateKey'])
            ->getMock();

        $securitySessionInterface->method('getPrivateKey')
            ->willReturn($this->privateKey);

        /** @noinspection PhpParamsInspection */
        $this->security->setSecuritySession($securitySessionInterface);

        $this->assertEquals($this->privateKey, $this->security->getSecuritySession()->getPrivateKey(1,1));
    }

    /**
     * @throws Exception
     */
    public function testGetSecurityClient() : void
    {
        /** @var MockObject|SecurityClientInterface $securityClientInterface */
        $securityClientInterface = $this->getMockBuilder(SecurityClientInterface::class)
            ->onlyMethods(['getSecret'])
            ->getMock();

        $securityClientInterface->method('getSecret')
            ->willReturn($this->clientSecret);

        $this->security->setSecurityClient($securityClientInterface);

        $this->assertEquals($this->clientSecret, $this->security->getSecurityClient()->getSecret(1));
    }

    public function testGetSetClientId() : void
    {
        $this->security->setClientId($this->clientId);
        $this->assertEquals($this->clientId, $this->security->getClientId());
    }

    public function testGetSetClientSecret() : void
    {
        $this->security->setClientSecret($this->clientSecret);
        $this->assertEquals($this->clientSecret, $this->security->getClientSecret());
    }

    public function testGetSetPublicKey() : void
    {
        $this->security->setPublicKey($this->publicKey);
        $this->assertEquals($this->publicKey, $this->security->getPublicKey());
    }

    public function testGetSetPrivateKey() : void
    {
        $this->security->setPrivateKey($this->privateKey);
        $this->assertEquals($this->privateKey, $this->security->getPrivateKey());
    }

    public function testDestroyStatics() : void
    {
        $this->security->setClientId($this->clientId);
        $this->security->setClientSecret($this->clientSecret);
        $this->security->setPublicKey($this->publicKey);
        $this->security->setPrivateKey($this->privateKey);
        $this->security->destroyStatics();
        $this->assertNull($this->security->getClientId());
        $this->assertNull($this->security->getClientSecret());
        $this->assertNull($this->security->getPublicKey());
        $this->assertNull($this->security->getPrivateKey());
    }

    public function testEntrophyError() : void
    {
        $log = $this->services->logger()->error()->log(SecurityErrorEvents::ENTROPY_EXCEPTION('', new Exception('')));
        $this->assertEquals('1', $log->getMessageCode());
    }
}