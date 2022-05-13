# Eibly Class - Crypt

## Using
```php
use Eibly\Crypt\Crypt;

$crypt = new Crypt("your secret key");

$value = $crypt->encrypt("content");
// $value: MDI2NTYwYTM5N2FiZWY0MDRmM2I5ZDU2OTM5OTg!NmRiZTYVZAuvIFt2Xm@eVug0eN)!A
$decrypted_value = $crypt->decrypt($value);
// $decrypted_value: content
```
# Defaults:
By default the salt mode will be used, but be careful.
When running the first time, it will create a json file with an array of salts.
Once stored, it will be used to decrypt. Be aware that deleting the file will make it impossible to decrypt the string in the future.

## Functions
```php
function setSaltStatus(bool $salt): void {...}
function getSaltStatus(): bool {...}
function setHash(string $hash): void {...}
function getHash(): string {...}
function setKey(string $key): void {...}
function getKey(): string {...}
function setMethod(string $method): void {...}
function getMethod(): string {...}
function doGenerateSalts(int $c = 16, int $l = 8): array {...}
function doGenerateSalt(int $len = 8): array {...}
function encrypt(mixed $string): string {...}
function decrypt($h): ?string {...}
```


---------
