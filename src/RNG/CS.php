<?php

namespace Eibly\Utils\RNG;

class CS implements IRNG
{
    /**
     * {@inheritdoc}
     */
    public function getRandomBytes(int $length): string
    {
        return random_bytes($length); // PHP7+
    }

    /**
     * {@inheritdoc}
     */
    public function isCryptographicallySecure(): bool
    {
        return true;
    }
}
