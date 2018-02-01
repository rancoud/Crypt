# Crypt Package

[![Build Status](https://travis-ci.org/rancoud/Crypt.svg?branch=master)](https://travis-ci.org/rancoud/Crypt) [![Coverage Status](https://coveralls.io/repos/github/rancoud/Crypt/badge.svg?branch=master)](https://coveralls.io/github/rancoud/Crypt?branch=master)

Crypt.  

## Installation
```php
composer require rancoud/crypt
```

## How to use it?
```php

```

## Crypt Constructor
### Settings
#### Mandatory
| Parameter | Type | Description |
| --- | --- | --- |
|  |  |  |

#### Optionnals
| Parameter | Type | Default value | Description |
| --- | --- | --- | --- |
|  |  |  |  |

## Crypt Methods
### General Commands  
* method(name: type, [optionnal: type = defalut]):outputType  


## How to Dev
### Linux
#### Coding Style
./vendor/bin/phpcbf  
./vendor/bin/phpcs  
./vendor/bin/php-cs-fixer fix --diff  
#### Unit Testing
./vendor/bin/phpunit --colors  
#### Code Coverage
##### Local
./vendor/bin/phpunit --colors --coverage-html ./coverage
##### Coveralls.io
./vendor/bin/phpunit --colors --coverage-text --coverage-clover build/logs/clover.xml  

### Windows
#### Coding Style
"vendor/bin/phpcbf.bat"  
"vendor/bin/phpcs.bat"  
"vendor/bin/php-cs-fixer.bat" fix --diff   
#### Unit Testing
"vendor/bin/phpunit.bat" --colors  
#### Code Coverage
##### Local
"vendor/bin/phpunit.bat" --colors --coverage-html ./coverage
##### Coveralls.io
"vendor/bin/phpunit.bat" --colors --coverage-text --coverage-clover build/logs/clover.xml  