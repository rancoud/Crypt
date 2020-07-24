# Crypt Package

![Packagist PHP Version Support](https://img.shields.io/packagist/php-v/rancoud/crypt)
[![Packagist Version](https://img.shields.io/packagist/v/rancoud/crypt)](https://packagist.org/packages/rancoud/crypt)
[![Packagist Downloads](https://img.shields.io/packagist/dt/rancoud/crypt)](https://packagist.org/packages/rancoud/crypt)
[![Composer dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](https://github.com/rancoud/Crypt/blob/master/composer.json)
[![Test workflow](https://img.shields.io/github/workflow/status/rancoud/crypt/test?label=test&logo=github)](https://github.com/rancoud/crypt/actions?workflow=test)
[![Codecov](https://img.shields.io/codecov/c/github/rancoud/crypt?logo=codecov)](https://codecov.io/gh/rancoud/crypt)
[![composer.lock](https://poser.pugx.org/rancoud/crypt/composerlock)](https://packagist.org/packages/rancoud/crypt)

Crypt using Argon2id by default with Argon2i and bcrypt in fallback.  

## Installation
```php
composer require rancoud/crypt
```

## How to use it?
```php
$password = 'my_password';
$hash = Crypt::hash($password);
$result = Crypt::verify($password, $hash);

// use only Argon2i
Crypt::useArgon2i();

// use only bcrypt
Crypt::useBcrypt();
```

## Crypt
### Static Methods  
* getCharactersForRandomString(): string  
* getCurrentAlgo(): int  
* getOptionsArgon2i(): array  
* getOptionsBcrypt(): array  
* getRandomString([length: int = 64]): string  
* hash(password: string): string  
* needsRehash(hash: string): bool  
* setCharactersForRandomString(characters: string): void  
* setOptionArgon2iMemoryCost(bytes: int): void  
* setOptionArgon2iThreads(threads: int): void  
* setOptionArgon2iTimeCost(time: int): void  
* setOptionBcryptCost(rounds: int): void  
* useArgon2id(): void  
* useArgon2i(): void  
* useBcrypt(): void  
* verify(password: string, hash: string): bool  

## How to Dev
`composer ci` for php-cs-fixer and phpunit and coverage  
`composer lint` for php-cs-fixer  
`composer test` for phpunit and coverage
