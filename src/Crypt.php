<?php

declare(strict_types=1);

namespace Rancoud\Crypt;

/**
 * Class Crypt.
 */
class Crypt
{
    protected static $algo = PASSWORD_ARGON2I;

    protected static $options = [
        'memory_cost' => 1 << 17, // 128 Mb
        'time_cost'   => 4,
        'threads'     => 3,
    ];

    protected static $caracters = 'abcdefghijklmnopqrstuvwxyz0123456789';

    /**
     * @param string $password
     *
     * @return string
     */
    public static function hash(string $password): string
    {
        return password_hash($password, static::$algo, static::$options);
    }

    /**
     * @param string $password
     * @param string $hash
     *
     * @return bool
     */
    public static function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * @param string $hash
     *
     * @return bool
     */
    public static function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, static::$algo, static::$options);
    }

    /**
     * @param int $length
     *
     * @return string
     */
    public static function getRandomString(int $length = 64): string
    {
        $string = '';
        $countCaracters = mb_strlen(static::$caracters) - 1;

        for ($i = 0; $i < $length; ++$i) {
            $string .= static::$caracters[rand(0, $countCaracters)];
        }

        return $string;
    }

    /*public static function encrypt($data)
    {
    }

    public static function decrypt($data)
    {
    }*/

    /**
     * @param int $value
     */
    public static function setOptionMemoryCost(int $value): void
    {
        static::$options['memory_cost'] = $value;
    }

    /**
     * @param int $value
     */
    public static function setOptionTimeCost(int $value): void
    {
        static::$options['time_cost'] = $value;
    }

    /**
     * @param int $value
     */
    public static function setOptionThreads(int $value): void
    {
        static::$options['threads'] = $value;
    }

    /**
     * @return array
     */
    public static function getOptions(): array
    {
        return static::$options;
    }

    /**
     * @param string $caracters
     */
    public static function setCaracters(string $caracters): void
    {
        static::$caracters = $caracters;
    }

    /**
     * @return string
     */
    public static function getCaracters(): string
    {
        return static::$caracters;
    }
}
