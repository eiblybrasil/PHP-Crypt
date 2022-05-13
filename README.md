# Class - Crypt

## Example

```
<?php
use Eibly\Crypt\Crypt;

$crypt = new Crypt("your secret key");

$value = $crypt->encrypt("crypted");

$decrypted_value = $crypt->decrypt($value);

```

---------
