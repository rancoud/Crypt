# Crypt Package

[![Build Status](https://travis-ci.org/rancoud/Crypt.svg?branch=master)](https://travis-ci.org/rancoud/Crypt) [![Coverage Status](https://coveralls.io/repos/github/rancoud/Crypt/badge.svg?branch=master)](https://coveralls.io/github/rancoud/Crypt?branch=master)

Crypt using Argon2i by default with bcrypt in fallback.  

## Installation
```php
composer require rancoud/crypt
```

## How to use it?
```php
$password = 'my_password';
$hash = Crypt::hash($password);
$result = Crypt::verify($password, $hash);

// use only bcrypt
Crypt::useBcrypt();
```

## Crypt Methods
### General Commands  
* useArgon2i(): void  
* useBcrypt(): void  
* hash(password: string): string  
* verify(password: string, hash: string): bool  
* needsRehash(hash: string): bool  
* getRandomString([length: int = 64]): string  
* setOptionArgon2iMemoryCost(bytes: int): void  
* setOptionArgon2iTimeCost(time: int): void  
* setOptionArgon2iThreads(threads: int): void  
* getOptionsArgon2i(): array  
* setOptionBcryptCost(rounds: int): void  
* getOptionsBcrypt(): array  
* setCaracters(caracters: string): void  
* getCaracters(): string  
* getCurrentAlgo(): int  


## How to Dev
`./run_all_commands.sh` for php-cs-fixer and phpunit and coverage  
`./run_php_unit_coverage.sh` for phpunit and coverage 
