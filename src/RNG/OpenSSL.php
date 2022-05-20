<?php

namespace Eibly\Utils\RNG;

class OpenSSL implements IRNG
{
    /** @var bool */
    private $requirestrong;

    /**
     * @param bool $requirestrong
     */
    public function __construct(bool $requirestrong = true)
    {
        $this->requirestrong = $requirestrong;
    }

    /**
     * {@inheritdoc}
     */
    public function getRandomBytes(int $length): string
    {
        $result = \openssl_random_pseudo_bytes($length, $crypto_strong);
        if ($this->requirestrong && ($crypto_strong === false)) {
            throw new \Exception('openssl_random_pseudo_bytes returned non-cryptographically strong value');
        }
        if ($result === false) {
            throw new \Exception('openssl_random_pseudo_bytes returned an invalid value');
        }
        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function isCryptographicallySecure(): bool
    {
        return $this->requirestrong;
    }
}
