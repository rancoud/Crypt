<?php

declare(strict_types=1);

namespace Rancoud\Crypt\Test;

use Exception;
use PHPUnit\Framework\TestCase;
use Rancoud\Crypt\Crypt;
use Rancoud\Crypt\CryptException;

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

        if (Crypt::getCurrentAlgo() === 2) {
            $hash = str_replace('9$m=1024,t=2,p=2$', '9$m=512,t=1,p=1$', $hash);
        } else {
            $hash = str_replace('$2y$12$', '$2y$05$', $hash);
        }
        $result = Crypt::needsRehash($hash);
        static::assertTrue($result);
    }

    public function testGetRandomString()
    {
        $randomString = Crypt::getRandomString();
        static::assertSame(64, mb_strlen($randomString));

        $randomString = Crypt::getRandomString(105);
        static::assertSame(105, mb_strlen($randomString));
    }

    public function testSetOptionMemoryCost()
    {
        Crypt::setOptionArgon2iMemoryCost(128);
        $options = Crypt::getOptionsArgon2i();
        static::assertSame(128, $options['memory_cost']);

        static::expectException(Exception::class);
        static::expectExceptionMessage('Memory cost is too small: 0 bytes');

        Crypt::setOptionArgon2iMemoryCost(0);
    }

    public function testSetOptionTimeCost()
    {
        Crypt::setOptionArgon2iTimeCost(3);
        $options = Crypt::getOptionsArgon2i();
        static::assertSame(3, $options['time_cost']);

        static::expectException(Exception::class);
        static::expectExceptionMessage('Time cost is too small: 0');

        Crypt::setOptionArgon2iTimeCost(0);
    }

    public function testSetOptionThreads()
    {
        Crypt::setOptionArgon2iThreads(5);
        $options = Crypt::getOptionsArgon2i();
        static::assertSame(5, $options['threads']);

        static::expectException(Exception::class);
        static::expectExceptionMessage('Number of threads is too small: 0');

        Crypt::setOptionArgon2iThreads(0);
    }

    public function testSetGetCaracters()
    {
        Crypt::setCaractersForRandomString('aze');
        $caracters = Crypt::getCaractersForRandomString();
        static::assertSame('aze', $caracters);
    }

    public function testBigPassword()
    {
        if (defined('PASSWORD_ARGON2I')) {
            Crypt::useArgon2i();

            $password = Crypt::getRandomString(1000);
            $hash = Crypt::hash($password);
            $result = Crypt::verify(mb_substr($password, 0, 1000), $hash);
            static::assertTrue($result);
            $result = Crypt::verify(mb_substr($password, 0, 999), $hash);
            static::assertFalse($result);
        }

        Crypt::useBcrypt();

        static::expectException(CryptException::class);
        static::expectExceptionMessage('Password too long for bcrypt (72 max): 1000 chars');

        $password = Crypt::getRandomString(1000);
        Crypt::hash($password);
    }

    public function testHashFailure()
    {
        if (defined('PASSWORD_ARGON2I')) {
            Crypt::useArgon2i();

            static::expectException(CryptException::class);
            static::expectExceptionMessage('Hash Failure');

            Crypt::setOptionArgon2iThreads(999999);
            Crypt::hash('toto');
        } else {
            static::assertTrue(true);
        }
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
        Crypt::useBcrypt();
        $hash = Crypt::hash('toto');
        $result = Crypt::verify('toto', $hash);
        static::assertTrue($result);

        $hash = Crypt::hash('okok');
        $result = Crypt::verify('toto', $hash);
        static::assertFalse($result);
    }

    public function testNeedsRehashBcrypt()
    {
        Crypt::useBcrypt();
        $hash = Crypt::hash('toto');
        $result = Crypt::needsRehash($hash);
        static::assertFalse($result);

        $hash = str_replace('$2y$12$', '$2y$05$', $hash);
        $result = Crypt::needsRehash($hash);
        static::assertTrue($result);
    }

    public function testSetGetOptionBcryptCost()
    {
        Crypt::setOptionBcryptCost(5);
        $options = Crypt::getOptionsBcrypt();
        static::assertSame(5, $options['cost']);
    }

    public function testSetOptionBcryptCostExceptionLowRounds()
    {
        static::expectException(Exception::class);
        static::expectExceptionMessage('Invalid number of rounds (between 4 and 31): 3');

        Crypt::setOptionBcryptCost(3);
    }

    public function testSetOptionBcryptCostExceptionHighRounds()
    {
        static::expectException(Exception::class);
        static::expectExceptionMessage('Invalid number of rounds (between 4 and 31): 32');

        Crypt::setOptionBcryptCost(32);
    }

    public function testHashExceptionPasswordTooLong()
    {
        Crypt::useBcrypt();

        static::expectException(Exception::class);
        static::expectExceptionMessage('Password too long');

        Crypt::hash('azertyuiopazertyuiopazertyuiopazertyuiopazertyuiopazertyuiopazertyuiopazertyuiop');
    }

    public function testUseArgon2i()
    {
        Crypt::useArgon2i();
        static::assertSame(2, Crypt::getCurrentAlgo());
    }
}
