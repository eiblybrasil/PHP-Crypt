<?php

namespace Eibly\Utils\RNG;

class Hash implements IRNG
{
    /** @var string */
    private $algorithm;

    /**
     * @param string $algorithm
     */
    public function __construct($algorithm = "sha256")
    {
        if (!\in_array($algorithm, \array_values(\hash_algos()), true)) {
            throw new \Exception('Unsupported algorithm specified');
        }
        $this->algorithm = $algorithm;
    }

    /**
     * {@inheritdoc}
     */
    public function getRandomBytes(int $length): string
    {
        $result = '';
        $hash = mt_rand();
        for ($i = 0; $i < $length; $i++) {
            $hash = hash($this->algorithm, $hash . mt_rand(), true);
            $result .= $hash[mt_rand(0, strlen($hash) - 1)];
        }
        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function isCryptographicallySecure(): bool
    {
        return false;
    }
}
