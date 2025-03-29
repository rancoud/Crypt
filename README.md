# Crypt Package

![Packagist PHP Version Support](https://img.shields.io/packagist/php-v/rancoud/crypt)
[![Packagist Version](https://img.shields.io/packagist/v/rancoud/crypt)](https://packagist.org/packages/rancoud/crypt)
[![Packagist Downloads](https://img.shields.io/packagist/dt/rancoud/crypt)](https://packagist.org/packages/rancoud/crypt)
[![Composer dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](https://github.com/rancoud/Crypt/blob/master/composer.json)
[![Test workflow](https://img.shields.io/github/actions/workflow/status/rancoud/crypt/test.yml?branch=master)](https://github.com/rancoud/crypt/actions/workflows/test.yml)
[![Codecov](https://img.shields.io/codecov/c/github/rancoud/crypt?logo=codecov)](https://codecov.io/gh/rancoud/crypt)

Crypt using Argon2id by default with Argon2i and bcrypt in fallback.  

## Installation
```php
composer require rancoud/crypt
```

## How to use it?
```php
use Rancoud\Crypt\Crypt;

$password = 'my_password';
$hash = Crypt::hash($password);
$result = Crypt::verify($password, $hash);

// use only Argon2i
Crypt::useArgon2i();

// use only bcrypt
Crypt::useBcrypt();
```

## Crypt
### Main functions
Hashs the password according to the selected algorithm.
```php
public static function hash(string $password): string
```

Checks whether the hash needs to be rehash to match the selected algorithm and options.
```php
public static function needsRehash(string $hash): bool
```

Checks if password and hash match.
```php
public static function verify(string $password, string $hash): bool
```

### Algorithms
Returns current algorithm.  
Possible values are `argon2id`, `argon2i` or `2y`.
```php
public static function getCurrentAlgo(): string
```

Sets the algorithm to `argon2id`.
```php
public static function useArgon2id(): void
```

Sets the algorithm to `argon2i`.
```php
public static function useArgon2i(): void
```

Sets the algorithm to `2y` (bcrypt).
```php
public static function useBcrypt(): void
```

### Options
Sets memory cost for `argon2id` and `argon2i`.<br>
Must be equal or greater than 8.
```php
public static function setOptionArgon2iMemoryCost(int $bytes): void
```

Sets number of threads for `argon2id` and `argon2i`.<br>
Must be equal or greater than 1.
```php
public static function setOptionArgon2iThreads(int $threads): void
```

Sets time cost for `argon2id` and `argon2i`.<br>
Must be equal or greater than 1.
```php
public static function setOptionArgon2iTimeCost(int $time): void
```

Sets rounds cost for `2y` (bcrypt).<br>
Must be between 4 and 31.
```php
public static function setOptionBcryptCost(int $rounds): void
```

Returns options for `argon2id` and `argon2i`.
```php
public static function getOptionsArgon2i(): array
```

Returns options for `2y` (bcrypt).
```php
public static function getOptionsBcrypt(): array
```

### Random string
Returns a fixed-size string containing random characters from the preselection.  
The default character pool is !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_``abcdefghijklmnopqrstuvwxyz{|}~.
```php
public static function getRandomString(int $length = 64, ?string $characters = null): string
```

Returns the character pool.
```php
public static function getCharactersForRandomString(): string
```

Sets the character pool.
```php
public static function setCharactersForRandomString(string $characters): void
```

## How to Dev
`composer ci` for php-cs-fixer and phpunit and coverage  
`composer lint` for php-cs-fixer  
`composer test` for phpunit and coverage
