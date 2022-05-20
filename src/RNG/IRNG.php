<?php

namespace Eibly\Utils\RNG;

interface IRNG
{
    /**
     * @param int $bytecount the number of bytes of randomness to return
     *
     * @return string the random bytes
     */
    public function getRandomBytes(int $length): string;

    /**
     * @return bool whether this provider is cryptographically secure
     */
    public function isCryptographicallySecure(): bool;
}