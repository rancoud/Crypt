<?php

declare(strict_types=1);

namespace Rancoud\Crypt\Test;

use Exception;
use PHPUnit\Framework\TestCase;
use Rancoud\Crypt\Crypt;

/**
 * Class CryptTest.
 */
class CryptTest extends TestCase
{
    public function testHash()
    {
        $hash = Crypt::hash('toto');
        static::assertNotFalse($hash);
    }

    public function testVerify()
    {
        $hash = Crypt::hash('toto');
        $result = Crypt::verify('toto', $hash);
        static::assertTrue($result);

        $hash = Crypt::hash('okok');
        $result = Crypt::verify('toto', $hash);
        static::assertFalse($result);
    }

    public function testNeedsRehash()
    {
        $hash = Crypt::hash('toto');
        $result = Crypt::needsRehash($hash);
        static::assertFalse($result);

        $hash = str_replace('9$m=1024,t=2,p=2$', '9$m=512,t=1,p=1$', $hash);
        $result = Crypt::needsRehash($hash);
        static::assertTrue($result);
    }

    public function testGetRandomString()
    {
        $randomString = Crypt::getRandomString();
        static::assertEquals(64, mb_strlen($randomString));

        $randomString = Crypt::getRandomString(105);
        static::assertEquals(105, mb_strlen($randomString));
    }

    public function testSetOptionMemoryCost()
    {
        Crypt::setOptionArgon2iMemoryCost(128);
        $options = Crypt::getOptionsArgon2i();
        static::assertEquals(128, $options['memory_cost']);

        static::expectException(Exception::class);
        Crypt::setOptionArgon2iMemoryCost(0);
    }

    public function testSetOptionTimeCost()
    {
        Crypt::setOptionArgon2iTimeCost(3);
        $options = Crypt::getOptionsArgon2i();
        static::assertEquals(3, $options['time_cost']);

        static::expectException(Exception::class);
        Crypt::setOptionArgon2iTimeCost(0);
    }

    public function testSetOptionThreads()
    {
        Crypt::setOptionArgon2iThreads(5);
        $options = Crypt::getOptionsArgon2i();
        static::assertEquals(5, $options['threads']);

        static::expectException(Exception::class);
        Crypt::setOptionArgon2iThreads(0);
    }

    public function testGetOptions()
    {
        $options = Crypt::getOptionsArgon2i();
        static::assertEquals(128, $options['memory_cost']);
        static::assertEquals(3, $options['time_cost']);
        static::assertEquals(5, $options['threads']);
    }

    public function testSetCaracters()
    {
        Crypt::setCaracters('aze');
        $caracters = Crypt::getCaracters();
        static::assertEquals('aze', $caracters);
    }

    public function testGetCaracters()
    {
        $caracters = Crypt::getCaracters();
        static::assertEquals('aze', $caracters);
    }

    public function testBigPassword()
    {
        $password = Crypt::getRandomString(1000);
        $hash = Crypt::hash($password);
        $result = Crypt::verify(mb_substr($password, 0, 1000), $hash);
        static::assertTrue($result);
        $result = Crypt::verify(mb_substr($password, 0, 999), $hash);
        static::assertFalse($result);
    }

    public function testHashFailure()
    {
        static::expectException(Exception::class);
        Crypt::setOptionArgon2iThreads(999999);
        Crypt::hash('toto');
    }

    // bcrypt part
    public function testHashBcrypt()
    {
        Crypt::useBcrypt();
        $hash = Crypt::hash('toto');
        static::assertNotFalse($hash);
    }

    public function testVerifyBcrypt()
    {
        $hash = Crypt::hash('toto');
        $result = Crypt::verify('toto', $hash);
        static::assertTrue($result);

        $hash = Crypt::hash('okok');
        $result = Crypt::verify('toto', $hash);
        static::assertFalse($result);
    }

    public function testNeedsRehashBcrypt()
    {
        $hash = Crypt::hash('toto');
        $result = Crypt::needsRehash($hash);
        static::assertFalse($result);
        
        $hash = str_replace('$2y$10$', '$2y$05$', $hash);
        $result = Crypt::needsRehash($hash);
        static::assertTrue($result);
    }

    public function testSetOptionBcryptCost()
    {
        Crypt::setOptionBcryptCost(5);
        $options = Crypt::getOptionsBcrypt();
        static::assertEquals(5, $options['cost']);
    }

    public function testSetOptionBcryptCostExceptionLowRounds()
    {
        static::expectException(Exception::class);
        Crypt::setOptionBcryptCost(3);
    }

    public function testSetOptionBcryptCostExceptionHighRounds()
    {
        static::expectException(Exception::class);
        Crypt::setOptionBcryptCost(32);
    }
    
    public function testGetOptionsBcrypt()
    {
        $options = Crypt::getOptionsBcrypt();
        static::assertEquals(5, $options['cost']);
    }

    public function testHashExceptionPasswordTooLong()
    {
        static::expectException(Exception::class);
        Crypt::hash("azertyuiopazertyuiopazertyuiopazertyuiopazertyuiopazertyuiopazertyuiopazertyuiop");
    }
    
    public function testUseArgon2i()
    {
        Crypt::useArgon2i();
        static::assertEquals(2, Crypt::getCurrentAlgo());
    }

}
