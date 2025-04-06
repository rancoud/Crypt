<?php

declare(strict_types=1);

namespace Rancoud\Crypt;

/**
 * Class Crypt.
 */
class Crypt
{
    /**
     * @var int Maximum characters length for `2y` (bcrypt) to process.<br>
     *          Bcrypt algorithm can not use more than 72 characters.
     */
    protected const MAX_LENGTH_BCRYPT = 72;

    /**
     * @var int Minimum value for memory cost
     */
    protected const MIN_MEMORY_COST = 8;

    /**
     * @var int Minimum value for time cost
     */
    protected const MIN_TIME_COST = 1;

    /**
     * @var int Minimum value for threads
     */
    protected const MIN_THREADS = 1;

    /**
     * @var int Minimum value for rounds
     */
    protected const MIN_ROUNDS = 4;

    /**
     * @var int Maximum value for rounds
     */
    protected const MAX_ROUNDS = 31;

    /**
     * @var string Value of PASSWORD_ARGON2ID
     */
    protected static string $algoArgon2id = 'argon2id';

    /**
     * @var string Value of PASSWORD_ARGON2I
     */
    protected static string $algoArgon2i = 'argon2i';

    /**
     * @var string Value of PASSWORD_BCRYPT
     */
    protected static string $algoBcrypt = '2y';

    /**
     * @var string Default algorithm to use is `argon2id`
     */
    protected static string $algoCurrent = 'argon2id';

    /**
     * @var bool By default algorithm is not fixed by the user
     */
    protected static bool $algoFixed = false;

    /**
     * @var array Default option values for `argon2i` and `argon2id`.<br>
     *            Use PASSWORD_ARGON2_DEFAULT_MEMORY_COST, PASSWORD_ARGON2_DEFAULT_TIME_COST
     *            and PASSWORD_ARGON2_DEFAULT_THREADS.
     */
    protected static array $optionsArgon2i = [
        'memory_cost' => 65536,
        'time_cost'   => 4,
        'threads'     => 1,
    ];

    /**
     * @var array Default option values for `2y` (bcrypt)
     */
    protected static array $optionsBcrypt = [
        'cost' => 12,
    ];

    /**
     * @var string Default pool of characters
     */
    protected static string $characters = '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ' .
        '[\]^_`abcdefghijklmnopqrstuvwxyz{|}~';

    /**
     * Hashs the password according to the selected algorithm.
     *
     * @throws CryptException
     */
    public static function hash(string $password): string
    {
        static::chooseAlgo();

        try {
            if (static::$algoCurrent === static::$algoArgon2i || static::$algoCurrent === static::$algoArgon2id) {
                $string = \password_hash($password, static::$algoCurrent, static::$optionsArgon2i);
            } else {
                if (\mb_strlen($password) > static::MAX_LENGTH_BCRYPT) {
                    throw new CryptException('Password too long');
                }
                $string = \password_hash($password, static::$algoCurrent, static::$optionsBcrypt);
            }
        } catch (\Exception $e) {
            if ($e->getMessage() === 'Password too long') {
                throw new CryptException(
                    \sprintf(
                        'Password too long for bcrypt (%d max): %d chars',
                        static::MAX_LENGTH_BCRYPT,
                        \mb_strlen($password)
                    )
                );
            }
            throw new CryptException('Hash Failure: ' . $e->getMessage());
        } catch (\Throwable $t) {
            throw new CryptException('Hash Failure: ' . $t->getMessage());
        }

        return $string;
    }

    /**
     * Checks if password and hash match.
     */
    public static function verify(string $password, string $hash): bool
    {
        return \password_verify($password, $hash);
    }

    /**
     * Checks whether the hash needs to be rehash to match the selected algorithm and options.
     */
    public static function needsRehash(string $hash): bool
    {
        static::chooseAlgo();

        if (static::$algoCurrent === static::$algoArgon2i || static::$algoCurrent === static::$algoArgon2id) {
            return \password_needs_rehash($hash, static::$algoCurrent, static::$optionsArgon2i);
        }

        return \password_needs_rehash($hash, static::$algoCurrent, static::$optionsBcrypt);
    }

    // region Options

    /**
     * Sets memory cost for `argon2id` and `argon2i`.<br>
     * Must be equal or greater than 8.
     *
     * @throws CryptException
     */
    public static function setOptionArgon2iMemoryCost(int $bytes): void
    {
        if ($bytes < static::MIN_MEMORY_COST) {
            throw new CryptException(\sprintf('Memory cost is too small: %d bytes', $bytes));
        }

        static::$optionsArgon2i['memory_cost'] = $bytes;

        $minThreads = \floor($bytes / 8);
        if (static::$optionsArgon2i['threads'] < $minThreads) {
            static::$optionsArgon2i['threads'] = $minThreads;
        }
    }

    /**
     * Sets time cost for `argon2id` and `argon2i`.<br>
     * Must be equal or greater than 1.
     *
     * @throws CryptException
     */
    public static function setOptionArgon2iTimeCost(int $time): void
    {
        if ($time < static::MIN_TIME_COST) {
            throw new CryptException(\sprintf('Time cost is too small: %d', $time));
        }

        static::$optionsArgon2i['time_cost'] = $time;
    }

    /**
     * Sets number of threads for `argon2id` and `argon2i`.<br>
     * Must be equal or greater than 1.
     *
     * @throws CryptException
     */
    public static function setOptionArgon2iThreads(int $threads): void
    {
        if ($threads < static::MIN_THREADS) {
            throw new CryptException(\sprintf('Number of threads is too small: %d', $threads));
        }
        static::$optionsArgon2i['threads'] = $threads;

        $minMemoryCost = $threads * 8;
        if (static::$optionsArgon2i['memory_cost'] < $minMemoryCost) {
            static::$optionsArgon2i['memory_cost'] = $minMemoryCost;
        }
    }

    /**
     * Returns options for `argon2id` and `argon2i`.
     */
    public static function getOptionsArgon2i(): array
    {
        return static::$optionsArgon2i;
    }

    /**
     * Sets rounds cost for `2y` (bcrypt).<br>
     * Must be between 4 and 31.
     *
     * @throws CryptException
     */
    public static function setOptionBcryptCost(int $rounds): void
    {
        if ($rounds < static::MIN_ROUNDS || $rounds > static::MAX_ROUNDS) {
            throw new CryptException(
                \sprintf(
                    'Invalid number of rounds (between %d and %d): %d',
                    static::MIN_ROUNDS,
                    static::MAX_ROUNDS,
                    $rounds
                )
            );
        }
        static::$optionsBcrypt['cost'] = $rounds;
    }

    /**
     * Returns options for `2y` (bcrypt).
     */
    public static function getOptionsBcrypt(): array
    {
        return static::$optionsBcrypt;
    }

    // endregion

    // region Random String

    /**
     * Returns a fixed-size string containing random characters from the preselection.<br>
     * The default character pool is !"#$%&\'()*+,-./0123456789:;<=>?@
     * ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~.
     *
     * @throws CryptException
     */
    public static function getRandomString(int $length = 64, ?string $characters = null): string
    {
        $initialCharacters = null;
        if ($characters !== null) {
            $initialCharacters = static::getCharactersForRandomString();
            static::setCharactersForRandomString($characters);
        }

        $string = '';
        $countCharacters = \mb_strlen(static::$characters) - 1;

        try {
            for ($i = 0; $i < $length; ++$i) {
                $string .= \mb_substr(static::$characters, \random_int(0, $countCharacters), 1);
            }
            // @codeCoverageIgnoreStart
        } catch (\Exception $e) {
            /* If an appropriate source of randomness cannot be found, an Exception will be thrown.
             * The list of randomness: https://www.php.net/manual/en/function.random-int.php
             */
            throw new CryptException($e->getMessage(), $e->getCode(), $e->getPrevious());
            // @codeCoverageIgnoreEnd
        } finally {
            if ($initialCharacters !== null) {
                static::setCharactersForRandomString($initialCharacters);
            }
        }

        return $string;
    }

    /**
     * Sets the character pool.
     *
     * @throws CryptException
     */
    public static function setCharactersForRandomString(string $characters): void
    {
        if ($characters === '') {
            throw new CryptException('Characters cannot be empty');
        }

        static::$characters = $characters;
    }

    /**
     * Returns the character pool.
     */
    public static function getCharactersForRandomString(): string
    {
        return static::$characters;
    }

    // endregion

    // region Set specific algorithm

    /**
     * Sets the algorithm to `argon2id`.
     */
    public static function useArgon2id(): void
    {
        static::$algoFixed = true;

        static::$algoCurrent = static::$algoArgon2id;
    }

    /**
     * Sets the algorithm to `argon2i`.
     */
    public static function useArgon2i(): void
    {
        static::$algoFixed = true;

        static::$algoCurrent = static::$algoArgon2i;
    }

    /**
     * Sets the algorithm to `2y` (bcrypt).
     */
    public static function useBcrypt(): void
    {
        static::$algoFixed = true;

        static::$algoCurrent = static::$algoBcrypt;
    }

    /**
     * Selects an algorithm if not defined by the user, in the following
     * order: `argon2id` or `argon2i` or `2y` (bcrypt).
     *
     * @codeCoverageIgnore
     * This function is ignore because it depends on how PHP has been built.
     */
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
     * Returns current algorithm.<br>
     * Possible values are `argon2id`, `argon2i` or `2y`.
     */
    public static function getCurrentAlgo(): string
    {
        return static::$algoCurrent;
    }

    // endregion
}
