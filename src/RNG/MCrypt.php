<?php

namespace Eibly\Utils\RNG;

class MCrypt implements IRNG
{
    /** @var int */
    private $source;

    /**
     * @param int $source
     */
    public function __construct($source = MCRYPT_DEV_URANDOM)
    {
        $this->source = $source;
    }

    /**
     * {@inheritdoc}
     */
    public function getRandomBytes(int $length): string
    {
        $result = @mcrypt_create_iv($length, $this->source);
        if ($result === false) {
            throw new \Exception('mcrypt_create_iv returned an invalid value');
        }
        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function isCryptographicallySecure(): bool
    {
        return true;
    }
}
