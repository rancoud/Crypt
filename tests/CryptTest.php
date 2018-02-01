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
    public function testConstruct()
    {
        new Crypt();
        static::assertTrue(true);
    }
}
