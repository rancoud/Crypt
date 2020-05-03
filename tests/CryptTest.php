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
    public function testHash(): void
    {
        try {
            $hash = Crypt::hash('toto');
            static::assertNotFalse($hash);
        } catch (CryptException $e) {
            /** @noinspection PhpUnhandledExceptionInspection */
            throw $e;
        }
    }

    public function testVerify(): void
    {
        try {
            $hash = Crypt::hash('toto');
            $result = Crypt::verify('toto', $hash);
            static::assertTrue($result);

            $hash = Crypt::hash('okok');
            $result = Crypt::verify('toto', $hash);
            static::assertFalse($result);
        } catch (CryptException $e) {
            /** @noinspection PhpUnhandledExceptionInspection */
            throw $e;
        }
    }

    public function testNeedsRehash(): void
    {
        try {
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
        } catch (CryptException $e) {
            /** @noinspection PhpUnhandledExceptionInspection */
            throw $e;
        }
    }

    public function testGetRandomString(): void
    {
        try {
            $randomString = Crypt::getRandomString();
            static::assertSame(64, mb_strlen($randomString));

            $randomString = Crypt::getRandomString(105);
            static::assertSame(105, mb_strlen($randomString));
        } catch (Exception $e) {
            /** @noinspection PhpUnhandledExceptionInspection */
            throw $e;
        }
    }

    public function testSetOptionMemoryCost(): void
    {
        $this->expectException(CryptException::class);
        $this->expectExceptionMessage('Memory cost is too small: 0 bytes');

        try {
            Crypt::setOptionArgon2iMemoryCost(128);
            $options = Crypt::getOptionsArgon2i();
            static::assertSame(128, $options['memory_cost']);

            Crypt::setOptionArgon2iMemoryCost(0);
        } catch (CryptException $e) {
            throw $e;
        }
    }

    public function testSetOptionTimeCost(): void
    {
        try {
            Crypt::setOptionArgon2iTimeCost(3);
            $options = Crypt::getOptionsArgon2i();
            static::assertSame(3, $options['time_cost']);
        } catch (CryptException $e) {
            /** @noinspection PhpUnhandledExceptionInspection */
            throw $e;
        }

        $this->expectException(CryptException::class);
        $this->expectExceptionMessage('Time cost is too small: 0');

        try {
            Crypt::setOptionArgon2iTimeCost(0);
        } catch (CryptException $e) {
            throw $e;
        }
    }

    public function testSetOptionThreads(): void
    {
        try {
            Crypt::setOptionArgon2iThreads(5);
            $options = Crypt::getOptionsArgon2i();
            static::assertSame(5, $options['threads']);
        } catch (CryptException $e) {
            /** @noinspection PhpUnhandledExceptionInspection */
            throw $e;
        }

        $this->expectException(CryptException::class);
        $this->expectExceptionMessage('Number of threads is too small: 0');

        try {
            Crypt::setOptionArgon2iThreads(0);
        } catch (CryptException $e) {
            throw $e;
        }
    }

    public function testSetGetCaracters(): void
    {
        Crypt::setCaractersForRandomString('aze');
        $caracters = Crypt::getCaractersForRandomString();
        static::assertSame('aze', $caracters);
    }

    public function testBigPassword(): void
    {
        if (defined('PASSWORD_ARGON2I')) {
            Crypt::useArgon2i();

            try {
                $password = Crypt::getRandomString(1000);
                $hash = Crypt::hash($password);
                $result = Crypt::verify(mb_substr($password, 0, 1000), $hash);
                static::assertTrue($result);
                $result = Crypt::verify(mb_substr($password, 0, 999), $hash);
                static::assertFalse($result);
            } catch (Exception $e) {
                /** @noinspection PhpUnhandledExceptionInspection */
                throw $e;
            }
        }

        Crypt::useBcrypt();

        $this->expectException(CryptException::class);
        $this->expectExceptionMessage('Password too long for bcrypt (72 max): 1000 chars');

        try {
            $password = Crypt::getRandomString(1000);
            Crypt::hash($password);
        } catch (CryptException $e) {
            throw $e;
        } catch (Exception $e) {
            /** @noinspection PhpUnhandledExceptionInspection */
            throw $e;
        }
    }

    public function testHashFailure(): void
    {
        if (defined('PASSWORD_ARGON2I')) {
            Crypt::useArgon2i();

            $this->expectException(CryptException::class);
            $this->expectExceptionMessage('Hash Failure');

            try {
                Crypt::setOptionArgon2iThreads(999999);
                Crypt::hash('toto');
            } catch (CryptException $e) {
                throw $e;
            }
        } else {
            static::assertTrue(true);
        }
    }

    // bcrypt part
    public function testHashBcrypt(): void
    {
        try {
            Crypt::useBcrypt();
            $hash = Crypt::hash('toto');
            static::assertNotFalse($hash);
        } catch (CryptException $e) {
            /** @noinspection PhpUnhandledExceptionInspection */
            throw $e;
        }
    }

    public function testVerifyBcrypt(): void
    {
        try {
            Crypt::useBcrypt();
            $hash = Crypt::hash('toto');
            $result = Crypt::verify('toto', $hash);
            static::assertTrue($result);

            $hash = Crypt::hash('okok');
            $result = Crypt::verify('toto', $hash);
            static::assertFalse($result);
        } catch (CryptException $e) {
            /** @noinspection PhpUnhandledExceptionInspection */
            throw $e;
        }
    }

    public function testNeedsRehashBcrypt(): void
    {
        try {
            Crypt::useBcrypt();
            $hash = Crypt::hash('toto');
            $result = Crypt::needsRehash($hash);
            static::assertFalse($result);

            $hash = str_replace('$2y$12$', '$2y$05$', $hash);
            $result = Crypt::needsRehash($hash);
            static::assertTrue($result);
        } catch (CryptException $e) {
            /** @noinspection PhpUnhandledExceptionInspection */
            throw $e;
        }
    }

    public function testSetGetOptionBcryptCost(): void
    {
        try {
            Crypt::setOptionBcryptCost(5);
            $options = Crypt::getOptionsBcrypt();
            static::assertSame(5, $options['cost']);
        } catch (CryptException $e) {
            /** @noinspection PhpUnhandledExceptionInspection */
            throw $e;
        }
    }

    public function testSetOptionBcryptCostExceptionLowRounds(): void
    {
        $this->expectException(CryptException::class);
        $this->expectExceptionMessage('Invalid number of rounds (between 4 and 31): 3');

        try {
            Crypt::setOptionBcryptCost(3);
        } catch (CryptException $e) {
            throw $e;
        }
    }

    public function testSetOptionBcryptCostExceptionHighRounds(): void
    {
        $this->expectException(CryptException::class);
        $this->expectExceptionMessage('Invalid number of rounds (between 4 and 31): 32');

        try {
            Crypt::setOptionBcryptCost(32);
        } catch (CryptException $e) {
            throw $e;
        }
    }

    public function testHashExceptionPasswordTooLong(): void
    {
        Crypt::useBcrypt();

        $this->expectException(CryptException::class);
        $this->expectExceptionMessage('Password too long');

        try {
            Crypt::hash('azertyuiopazertyuiopazertyuiopazertyuiopazertyuiopazertyuiopazertyuiopazertyuiop');
        } catch (CryptException $e) {
            throw $e;
        }
    }

    public function testUseArgon2i(): void
    {
        Crypt::useArgon2i();
        static::assertSame(2, Crypt::getCurrentAlgo());
    }
}
