# Crypt Package

![Packagist PHP Version Support](https://img.shields.io/packagist/php-v/rancoud/crypt)
[![Packagist Version](https://img.shields.io/packagist/v/rancoud/crypt)](https://packagist.org/packages/rancoud/crypt)
[![Packagist Downloads](https://img.shields.io/packagist/dt/rancoud/crypt)](https://packagist.org/packages/rancoud/crypt)
[![Build Status](https://travis-ci.org/rancoud/Crypt.svg?branch=master)](https://travis-ci.org/rancoud/Crypt)
[![Coverage Status](https://coveralls.io/repos/github/rancoud/Crypt/badge.svg?branch=master)](https://coveralls.io/github/rancoud/Crypt?branch=master)
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
`./run_all_commands.sh` for php-cs-fixer and phpunit and coverage  
`./run_php_unit_coverage.sh` for phpunit and coverage 
