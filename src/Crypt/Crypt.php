<?php

namespace Eibly\Crypt;

/**
 * Crypt wrapper
 *
 * Crypt
 * Cryptography functions
 *
 * @author Kleber Holtz <contact@eibly.com>
 *
 * @version 1
 */
class Crypt
{
    protected bool $salt = true;
    protected ?array $salts;
    protected int $salt_length = 6;
    protected int $salt_count = 48;
    private int $salt_enc_length;
    protected string $hash = "sha256";
    protected string $key = "";
    protected string $method = "aes-256-cbc";

    public function __construct(string $key = "", bool $salt = true, string $hash = "sha256", string $method = "aes-256-cbc")
    {
        foreach (array(
            'openssl_random_pseudo_bytes',
            'openssl_encrypt',
            'openssl_decrypt',
            'base64_encode',
            'base64_decode'
        ) as $f) {
            if (!\function_exists($f)) {
                throw new \Exception("The function $f is not available");
            }
        }
        $this->setHash($hash);
        $this->setKey($key);
        $this->setMethod($method);
        $this->setSaltStatus($salt);
        if ($this->salt) {
            $file = __DIR__ . "/salts.json";
            if (\file_exists($file)) {
                if (!$this->salts = \json_decode(file_get_contents($file), true)) {
                    throw new \Exception("Error reading salts file, please check the file permissions.");
                }
                if (!\is_array($this->salts)) {
                    throw new \Exception("Error reading salts file, invalid format.");
                }
                if (\count($this->salts) < $this->salt_count) {
                    $this->salts = \array_merge($this->salts, $this->doGenerateSalts($this->salt_count - \count($this->salts)));
                    if (\file_put_contents($file, \json_encode($this->salts), LOCK_EX) === false) {
                        throw new \Exception("Error writing salts file, please check the file permissions.");
                    }
                }
            } else {
                $this->salts = $this->doGenerateSalts($this->salt_count, $this->salt_length);
                if (\file_put_contents($file, \json_encode($this->salts), LOCK_EX) === false) {
                    throw new \Exception("Error writing salts file, please check the file permissions.");
                }
            }
        }
    }
    public function setSaltStatus(bool $salt): void
    {
        $this->salt = $salt;
    }
    public function getSaltStatus(): bool
    {
        return $this->salt;
    }
    public function setSaltLength(int $salt_length): void
    {
        $this->salt_length = $salt_length;
    }
    public function getSaltLength(): int
    {
        return $this->salt_length;
    }
    public function setSaltCount(int $salt_count): void
    {
        $this->salt_count = $salt_count;
    }
    public function getSaltCount(): int
    {
        return $this->salt_count;
    }
    public function setHash(string $hash): void
    {
        $hash = \strtolower($hash);
        if (!\in_array($hash, \hash_algos())) {
            throw new \Exception("The hash algorithm $hash is not available");
        }
        $this->hash = $hash;
    }
    public function getHash(): string
    {
        return $this->hash;
    }
    public function setKey(string $key): void
    {
        if (\strlen($key) < 8 && \strlen($key) > 256) {
            throw new \Exception("Key must be between 8 and 256 characters");
        }
        $this->key = $key;
    }
    public function getKey(): string
    {
        return $this->key;
    }
    public function setMethod(string $method): void
    {
        $method = \strtolower($method);
        if (!\in_array($method, \openssl_get_cipher_methods(false))) {
            throw new \Exception("Method not found");
        }
        $this->method = $method;
    }
    public function getMethod(): string
    {
        return $this->method;
    }
    protected function doGenerateSalts(int $count = 64, int $length = 8): array
    {
        $salts = array();
        for ($i = 0; $i < $count; $i++) {
            \array_push($salts, $this->doGenerateSalt($length));
        }
        return $salts;
    }
    protected function doGenerateSalt(int $length = 8): array
    {
        $r = array();
        foreach (array(
            \str_split("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
            \str_split("!\"#$%&'()*+,/:;<=>?@\\~[]^{}_")
        ) as $t) {
            if ($length > \count($t)) {
                throw new \Exception("The length must be greater than " . \count($t));
            }
            for ($i = 0; $i < $length; $i++) {
                if ($i === 0) {
                    $c = array();
                }
                $v = $t[\array_rand($t)];
                if (!\in_array($v, $c)) {
                    $c[] = $v;
                } else {
                    $i--;
                    continue;
                }
                if ($i === $length - 1) {
                    $r[] = \implode("", $c);
                    break;
                }
            }
        }
        return $r;
    }
    public function encrypt(string $str): string
    {
        $iv = \openssl_random_pseudo_bytes(16);
        $key = \hash($this->hash, $this->key, true);
        $enc = \openssl_encrypt($str, $this->method, $key, 0, $iv);
        $enc = \strtr($enc, '+/', '-.');
        $enc = \rtrim($enc, '=');
        $iv = \bin2hex($iv);
        $iv = \base64_encode($iv);
        $iv = \strtr($iv, '+/', '-.');
        $iv = \rtrim($iv, '=');
        $str = $iv . $enc;
        if ($this->salt) {
            $salt_rand = \array_rand($this->salts);
            $salt_enc = \base64_encode(\str_pad($salt_rand, \strlen($this->salt_count) + 1, 0, STR_PAD_LEFT));
            $salt_enc = \strtr($salt_enc, '+/', '-.');
            $salt_enc = \rtrim($salt_enc, '=');
            $this->salt_enc_length = \strlen($salt_enc);
            $str = $salt_enc . \str_replace(\str_split($this->salts[$salt_rand][0]), \str_split($this->salts[$salt_rand][1]), $str);
        }
        return $str;
    }
    public function decrypt(string $str): ?string
    {
        if ($this->salt) {
            $salt_enc = \substr($str, 0, $this->salt_enc_length);
            $salt_enc = \strtr($salt_enc, '-.', '+/');
            $salt_rand = \intval(\base64_decode($salt_enc));
            $str = \str_replace(\str_split($this->salts[$salt_rand][1]), \str_split($this->salts[$salt_rand][0]), $str);
            $str = \substr($str, $this->salt_enc_length);
        }
        $iv = \substr($str, 0, 43);
        $iv = \strtr($iv, '-.', '+/');
        $iv = \base64_decode($iv);
        $iv = \hex2bin($iv);
        $key = \hash($this->hash, $this->key, true);
        $dec = \substr($str, 43);
        $dec = \strtr($dec, '-.', '+/');
        $dec = \openssl_decrypt($dec, $this->method, $key, 0, $iv);
        if ($dec !== false) {
            return \strval($dec);
        }
        return null;
    }
}
