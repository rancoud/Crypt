<?php

declare(strict_types=1);

namespace Rancoud\Crypt\Test;

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

        /*$hash = Crypt::hash('tata');
        $result = Crypt::needsRehash($hash);
        static::assertTrue($result);*/
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
        Crypt::setOptionMemoryCost(60);
        $options = Crypt::getOptions();
        static::assertEquals(60, $options['memory_cost']);
    }

    public function testSetOptionTimeCost()
    {
        Crypt::setOptionTimeCost(50);
        $options = Crypt::getOptions();
        static::assertEquals(50, $options['time_cost']);
    }

    public function testSetOptionThreads()
    {
        Crypt::setOptionThreads(40);
        $options = Crypt::getOptions();
        static::assertEquals(40, $options['threads']);
    }

    public function testGetOptions()
    {
        $options = Crypt::getOptions();
        static::assertEquals(60, $options['memory_cost']);
        static::assertEquals(50, $options['time_cost']);
        static::assertEquals(40, $options['threads']);
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
}
