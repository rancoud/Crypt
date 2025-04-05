<?php

declare(strict_types=1);

namespace tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Rancoud\Crypt\Crypt;
use Rancoud\Crypt\CryptException;

/**
 * @runTestsInSeparateProcesses
 * Class CryptTest.
 */
#[RunTestsInSeparateProcesses]
class CryptTest extends TestCase
{
    // region Set specific algo

    public function testUseArgon2i(): void
    {
        Crypt::useArgon2i();

        static::assertSame('argon2i', Crypt::getCurrentAlgo());
    }

    public function testUseArgon2id(): void
    {
        Crypt::useBcrypt();
        Crypt::useArgon2id();

        static::assertSame('argon2id', Crypt::getCurrentAlgo());
    }

    // endregion

    // region Hash / Verify / Needs Rehash

    public static function dataCasesGeneric(): array
    {
        return [
            'Argon2id' => [
                'useAlgo'  => 'useArgon2id',
                'password' => 'my_password_argon_2id',
            ],
            'Argon2i' => [
                'useAlgo'  => 'useArgon2i',
                'password' => 'my_password_argon_2i',
            ],
            'Bcrypt' => [
                'useAlgo'  => 'useBcrypt',
                'password' => 'my_password_bcrypt',
            ],
        ];
    }

    /**
     * @dataProvider dataCasesGeneric
     *
     * @throws CryptException
     */
    #[DataProvider('dataCasesGeneric')]
    public function testHash(string $useAlgo, string $password): void
    {
        Crypt::$useAlgo();

        static::assertNotFalse(Crypt::hash($password));
    }

    /**
     * @dataProvider dataCasesGeneric
     *
     * @throws CryptException
     */
    #[DataProvider('dataCasesGeneric')]
    public function testVerifyValid(string $useAlgo, string $password): void
    {
        Crypt::$useAlgo();

        $hash = Crypt::hash($password);
        $passwordAgainstHashIsValid = Crypt::verify($password, $hash);

        static::assertTrue($passwordAgainstHashIsValid);
    }

    /**
     * @dataProvider dataCasesGeneric
     *
     * @throws CryptException
     */
    #[DataProvider('dataCasesGeneric')]
    public function testVerifyInvalid(string $useAlgo, string $password): void
    {
        Crypt::$useAlgo();

        $hash = Crypt::hash($password);
        $passwordAgainstHashIsNotValid = Crypt::verify('invalid_password', $hash);

        static::assertFalse($passwordAgainstHashIsNotValid);
    }

    /**
     * @dataProvider dataCasesGeneric
     *
     * @throws CryptException
     */
    #[DataProvider('dataCasesGeneric')]
    public function testNeedsRehash(string $useAlgo, string $password): void
    {
        Crypt::$useAlgo();

        $hash = Crypt::hash($password);
        $doNotNeedRehash = Crypt::needsRehash($hash);

        static::assertFalse($doNotNeedRehash);

        // modify hash options to trigger "needs Rehash"
        $currentAlgo = Crypt::getCurrentAlgo();
        if ($currentAlgo === 'argon2id' || $currentAlgo === 'argon2i') {
            $hash = \str_replace('9$m=65536,t=4,p=1$', '9$m=512,t=1,p=1$', $hash);
        } else {
            $hash = \str_replace('$2y$12$', '$2y$05$', $hash);
        }
        $needsRehash = Crypt::needsRehash($hash);

        static::assertTrue($needsRehash);
    }

    public static function dataCasesHashFailure(): array
    {
        return [
            'Argon2id' => [
                'useAlgo'      => 'useArgon2id',
                'password'     => 'my_password_argon_2id',
                'errorMessage' => 'Hash Failure',
            ],
            'Argon2i' => [
                'useAlgo'      => 'useArgon2i',
                'password'     => 'my_password_argon_2i',
                'errorMessage' => 'Hash Failure',
            ],
            'Bcrypt' => [
                'useAlgo'      => 'useBcrypt',
                'password'     => 'azertyuiopazertyuiopazertyuiopazertyuiopazertyuiopazertyuiopazertyuiopazertyuiop',
                'errorMessage' => 'Password too long',
            ]
        ];
    }

    /**
     * @dataProvider dataCasesHashFailure
     *
     * @throws CryptException
     */
    #[DataProvider('dataCasesHashFailure')]
    public function testHashFailure(string $useAlgo, string $password, string $errorMessage): void
    {
        Crypt::$useAlgo();

        $this->expectException(CryptException::class);
        $this->expectExceptionMessage($errorMessage);

        Crypt::setOptionArgon2iMemoryCost(999999999);
        Crypt::hash($password);
    }

    // endregion

    // region Options

    /**
     * @throws CryptException
     */
    public function testSetOptionMemoryCost(): void
    {
        Crypt::setOptionArgon2iMemoryCost(128);
        $options = Crypt::getOptionsArgon2i();
        static::assertSame(128, $options['memory_cost']);

        Crypt::setOptionArgon2iThreads(2);
        $options = Crypt::getOptionsArgon2i();
        static::assertSame(128, $options['memory_cost']);

        Crypt::setOptionArgon2iThreads(24);
        $options = Crypt::getOptionsArgon2i();
        static::assertSame(192, $options['memory_cost']);
    }

    public function testSetOptionMemoryCostCryptException(): void
    {
        $this->expectException(CryptException::class);
        $this->expectExceptionMessage('Memory cost is too small: 0 bytes');

        Crypt::setOptionArgon2iMemoryCost(0);
    }

    /**
     * @throws CryptException
     */
    public function testSetOptionTimeCost(): void
    {
        Crypt::setOptionArgon2iTimeCost(3);
        $options = Crypt::getOptionsArgon2i();

        static::assertSame(3, $options['time_cost']);
    }

    public function testSetOptionTimeCostCryptException(): void
    {
        $this->expectException(CryptException::class);
        $this->expectExceptionMessage('Time cost is too small: 0');

        Crypt::setOptionArgon2iTimeCost(0);
    }

    /**
     * @throws CryptException
     */
    public function testSetOptionThreads(): void
    {
        Crypt::setOptionArgon2iThreads(5);
        $options = Crypt::getOptionsArgon2i();
        static::assertSame(5, $options['threads']);
        static::assertSame(65536, $options['memory_cost']);

        Crypt::setOptionArgon2iMemoryCost(8);
        Crypt::setOptionArgon2iThreads(5);
        $options = Crypt::getOptionsArgon2i();
        static::assertSame(5, $options['threads']);
        static::assertSame(5 * 8, $options['memory_cost']);
    }

    public function testSetOptionThreadsCryptException(): void
    {
        $this->expectException(CryptException::class);
        $this->expectExceptionMessage('Number of threads is too small: 0');

        Crypt::setOptionArgon2iThreads(0);
    }

    /**
     * @throws CryptException
     */
    public function testSetGetOptionBcryptCost(): void
    {
        Crypt::setOptionBcryptCost(5);
        $options = Crypt::getOptionsBcrypt();

        static::assertSame(5, $options['cost']);
    }

    public function testSetOptionBcryptCostExceptionLowRounds(): void
    {
        $this->expectException(CryptException::class);
        $this->expectExceptionMessage('Invalid number of rounds (between 4 and 31): 3');

        Crypt::setOptionBcryptCost(3);
    }

    public function testSetOptionBcryptCostExceptionHighRounds(): void
    {
        $this->expectException(CryptException::class);
        $this->expectExceptionMessage('Invalid number of rounds (between 4 and 31): 32');

        Crypt::setOptionBcryptCost(32);
    }

    // endregion

    // region Random String

    /**
     * @throws CryptException
     */
    public function testSetGetCharacters(): void
    {
        Crypt::setCharactersForRandomString('aze');
        $characters = Crypt::getCharactersForRandomString();

        static::assertSame('aze', $characters);
    }

    public function testSetGetCharactersCryptException(): void
    {
        $this->expectException(CryptException::class);
        $this->expectExceptionMessage('Characters cannot be empty');

        Crypt::setCharactersForRandomString('');
    }

    /**
     * @throws CryptException
     */
    public function testGetRandomString(): void
    {
        $randomString = Crypt::getRandomString();
        static::assertSame(64, \mb_strlen($randomString));

        $randomString = Crypt::getRandomString(105);
        static::assertSame(105, \mb_strlen($randomString));

        Crypt::setCharactersForRandomString('‍привет');
        $randomString = Crypt::getRandomString(10);
        static::assertSame(10, \mb_strlen($randomString));

        Crypt::setCharactersForRandomString('صباح الخير');
        $randomString = Crypt::getRandomString(15);
        static::assertSame(15, \mb_strlen($randomString));

        Crypt::setCharactersForRandomString('숍訊昱穿刷奄剔㏆穽侘㈊섞昌侄從쒜');
        $randomString = Crypt::getRandomString(20);
        static::assertSame(20, \mb_strlen($randomString));

        $randomString = Crypt::getRandomString(25, 'a');
        static::assertSame(25, \mb_strlen($randomString));
        static::assertSame('숍訊昱穿刷奄剔㏆穽侘㈊섞昌侄從쒜', Crypt::getCharactersForRandomString());
        static::assertNotSame('a', Crypt::getCharactersForRandomString());
    }

    /**
     * @throws CryptException
     */
    public function testGetRandomStringCryptException(): void
    {
        $this->expectException(CryptException::class);
        $this->expectExceptionMessage('Characters cannot be empty');

        Crypt::getRandomString(25, '');
    }

    // endregion
}
