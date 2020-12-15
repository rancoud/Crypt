<?php

declare(strict_types=1);

namespace Rancoud\Crypt;

/**
 * Class Crypt.
 */
class Crypt
{
    protected const MAX_LENGTH_BCRYPT = 72;

    protected const MIN_MEMORY_COST = 16;
    protected const MIN_TIME_COST = 1;
    protected const MIN_THREADS = 1;

    protected const MIN_ROUNDS = 4;
    protected const MAX_ROUNDS = 31;

    protected static string $algoArgon2id = 'argon2id'; // PASSWORD_ARGON2ID
    protected static string $algoArgon2i = 'argon2i'; // PASSWORD_ARGON2I
    protected static string $algoBcrypt = '2y'; // PASSWORD_BCRYPT

    protected static string $algoCurrent = 'argon2id'; // by default use ARGON2ID
    protected static bool $algoFixed = false;

    protected static array $optionsArgon2i = [
        'memory_cost' => 65536, // PASSWORD_ARGON2_DEFAULT_MEMORY_COST
        'time_cost'   => 4, // PASSWORD_ARGON2_DEFAULT_TIME_COST
        'threads'     => 1, // PASSWORD_ARGON2_DEFAULT_THREADS
    ];

    protected static array $optionsBcrypt = [
        'cost' => 12,
    ];

    protected static string $characters = '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ' .
    '[\]^_`abcdefghijklmnopqrstuvwxyz{|}~';

    public static function useArgon2id(): void
    {
        static::$algoFixed = true;

        static::$algoCurrent = static::$algoArgon2id;
    }

    public static function useArgon2i(): void
    {
        static::$algoFixed = true;

        static::$algoCurrent = static::$algoArgon2i;
    }

    public static function useBcrypt(): void
    {
        static::$algoFixed = true;

        static::$algoCurrent = static::$algoBcrypt;
    }

    /**
     * @param string $password
     *
     * @throws CryptException
     *
     * @return string
     */
    public static function hash(string $password): string
    {
        $string = null;

        static::chooseAlgo();

        try {
            if (static::$algoCurrent === static::$algoArgon2i || static::$algoCurrent === static::$algoArgon2id) {
                $string = \password_hash($password, static::$algoCurrent, static::$optionsArgon2i);
            } else {
                if (\mb_strlen($password) > self::MAX_LENGTH_BCRYPT) {
                    /* @noinspection ThrowRawExceptionInspection */
                    throw new \Exception('Password too long');
                }
                $string = \password_hash($password, static::$algoCurrent, static::$optionsBcrypt);
            }
        } catch (\Exception $e) {
            if ($e->getMessage() === 'Password too long') {
                throw new CryptException(
                    \sprintf(
                        'Password too long for bcrypt (%d max): %d chars',
                        self::MAX_LENGTH_BCRYPT,
                        \mb_strlen($password)
                    )
                );
            }
            throw new CryptException('Hash Failure');
        }

        return $string;
    }

    /**
     * @param string $password
     * @param string $hash
     *
     * @return bool
     */
    public static function verify(string $password, string $hash): bool
    {
        return \password_verify($password, $hash);
    }

    /**
     * @param string $hash
     *
     * @return bool
     */
    public static function needsRehash(string $hash): bool
    {
        static::chooseAlgo();

        if (static::$algoCurrent === static::$algoArgon2i || static::$algoCurrent === static::$algoArgon2id) {
            return \password_needs_rehash($hash, static::$algoCurrent, static::$optionsArgon2i);
        }

        return \password_needs_rehash($hash, static::$algoCurrent, static::$optionsBcrypt);
    }

    /**
     * @param int $length
     *
     * @throws \Exception
     *
     * @return string
     */
    public static function getRandomString(int $length = 64): string
    {
        $string = '';
        $countCharacters = \mb_strlen(static::$characters) - 1;

        for ($i = 0; $i < $length; ++$i) {
            $string .= static::$characters[\random_int(0, $countCharacters)];
        }

        return $string;
    }

    /**
     * @param int $bytes
     *
     * @throws CryptException
     */
    public static function setOptionArgon2iMemoryCost(int $bytes): void
    {
        if ($bytes < self::MIN_MEMORY_COST) {
            throw new CryptException(\sprintf('Memory cost is too small: %d bytes', $bytes));
        }

        static::$optionsArgon2i['memory_cost'] = $bytes;
    }

    /**
     * @param int $time
     *
     * @throws CryptException
     */
    public static function setOptionArgon2iTimeCost(int $time): void
    {
        if ($time < self::MIN_TIME_COST) {
            throw new CryptException(\sprintf('Time cost is too small: %d', $time));
        }

        static::$optionsArgon2i['time_cost'] = $time;
    }

    /**
     * @param int $threads
     *
     * @throws CryptException
     */
    public static function setOptionArgon2iThreads(int $threads): void
    {
        if ($threads < self::MIN_THREADS) {
            throw new CryptException(\sprintf('Number of threads is too small: %d', $threads));
        }
        static::$optionsArgon2i['threads'] = $threads;
    }

    /**
     * @return array
     */
    public static function getOptionsArgon2i(): array
    {
        return static::$optionsArgon2i;
    }

    /**
     * @param int $rounds
     *
     * @throws CryptException
     */
    public static function setOptionBcryptCost(int $rounds): void
    {
        if ($rounds < self::MIN_ROUNDS || $rounds > self::MAX_ROUNDS) {
            throw new CryptException(
                \sprintf(
                    'Invalid number of rounds (between %d and %d): %d',
                    self::MIN_ROUNDS,
                    self::MAX_ROUNDS,
                    $rounds
                )
            );
        }
        static::$optionsBcrypt['cost'] = $rounds;
    }

    /**
     * @return array
     */
    public static function getOptionsBcrypt(): array
    {
        return static::$optionsBcrypt;
    }

    /**
     * @param string $characters
     */
    public static function setCharactersForRandomString(string $characters): void
    {
        static::$characters = $characters;
    }

    /**
     * @return string
     */
    public static function getCharactersForRandomString(): string
    {
        return static::$characters;
    }

    /** @codeCoverageIgnore  */
    protected static function chooseAlgo(): void
    {
        if (static::$algoFixed) {
            return;
        }

        if (\defined('PASSWORD_ARGON2ID')) {
            static::$algoCurrent = static::$algoArgon2id;
        } elseif (\defined('PASSWORD_ARGON2I')) {
            static::$algoCurrent = static::$algoArgon2i;
        } else {
            static::$algoCurrent = static::$algoBcrypt;
        }
    }

    /**
     * @return string
     */
    public static function getCurrentAlgo(): string
    {
        return static::$algoCurrent;
    }
}
