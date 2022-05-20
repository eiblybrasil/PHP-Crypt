<?php

namespace Eibly\Utils\RNG;

trait RNG
{
    private IRNG $rng_provider;
    public function getRNGProvider(IRNG $provider = null): IRNG
    {
        if (!isset($this->rng_provider)) {
            if (!\is_null($provider)) {
                return $this->rng_provider = $provider;
            } else if (\function_exists('random_bytes')) {
                return $this->rng_provider = new CS();
            } elseif (\function_exists('mcrypt_create_iv')) {
                return $this->rng_provider = new MCrypt();
            } elseif (\function_exists('openssl_random_pseudo_bytes')) {
                return $this->rng_provider = new OpenSSL();
            } elseif (\function_exists('hash')) {
                return $this->rng_provider = new Hash();
            }
            throw new \Exception("No suitable RNG provider found");
        } else {
            return $this->rng_provider;
        }
    }
}
