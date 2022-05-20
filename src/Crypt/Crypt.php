<?php

namespace Eibly\Crypt;

use Eibly\Utils\RNG\RNG;

/**
 * Crypt
 * Cryptography functions
 *
 * @throws \Exception
 * 
 * @author Kleber Holtz <contact@eibly.com>
 * @copyright Eibly LTDA
 * @license Apache 2.0
 *
 * @version 1.2
 */
class Crypt
{
    /**
     * Use the RNG to generate a random string
     */
    use RNG;

    /**
     * Class const variables
     * 
     * NOTE: Please, don't change these values
     */
    private const IV_LENGTH = 16;
    private const SALT_COUNT = 128;
    private const SALT_LENGTH = 8;

    /**
     * Class variables
     */
    private ?array $salts;
    private ?int $saltLength = null;
    private bool $useSalt = true;
    private string $hash = "sha256";
    private string $key = "";
    private string $method = "aes-256-cbc";

    /**
     * Class constructor
     */
    public function __construct(string $key = "", bool $useSalt = true, string $hash = "sha256", string $method = "aes-256-cbc")
    {
        $this->setHash($hash);
        $this->setKey($key);
        $this->setMethod($method);
        $this->setSaltStatus($useSalt);
    }

    /**
     * setSaltStatus()
     * Enable or disable the use of salts
     * 
     * @param bool $useSalt
     * 
     * @return void
     */
    public function setSaltStatus(bool $salt): void
    {
        $file = __DIR__ . "/salts.json";
        if ($this->useSalt = $salt) {
            if (\file_exists($file)) {
                if (!$this->salts = \json_decode(file_get_contents($file), true)) {
                    throw new \Exception("Error reading salts file, please check the file permissions.");
                }
                if (!\is_array($this->salts)) {
                    throw new \Exception("Error reading salts file, invalid format.");
                }
                if (\count($this->salts) < self::SALT_COUNT) {
                    $this->salts = \array_merge($this->salts, $this->doGenerateSalts(self::SALT_COUNT - \count($this->salts)));
                    if (\file_put_contents($file, \json_encode($this->salts), LOCK_EX) === false) {
                        throw new \Exception("Error writing salts file, please check the file permissions.");
                    }
                }
            } else {
                $this->salts = $this->doGenerateSalts(self::SALT_COUNT, self::SALT_LENGTH);
                if (\file_put_contents($file, \json_encode($this->salts), LOCK_EX) === false) {
                    throw new \Exception("Error writing salts file, please check the file permissions.");
                }
            }
        } elseif (\file_exists($file)) {
            if (!\unlink($file)) {
                throw new \Exception("Error removing salts file, please check the file permissions.");
            }
        }
    }

    /**
     * getSaltStatus()
     * Return the salt status
     * 
     * @return bool
     */
    public function getSaltStatus(): bool
    {
        return $this->useSalt;
    }

    /**
     * setHash()
     * Set the hash algorithm
     * 
     * @param string $hash
     * 
     * @return void
     */
    public function setHash(string $hash): void
    {
        $hash = \strtolower($hash);
        if (!\in_array($hash, \hash_algos())) {
            throw new \Exception("The hash algorithm $hash is not available");
        }
        $this->hash = $hash;
    }

    /**
     * getHash()
     * Return the hash algorithm
     * 
     * @return string
     */
    public function getHash(): string
    {
        return $this->hash;
    }

    /**
     * setKey()
     * Set the encryption key
     * 
     * @param string $key
     * 
     * @return void
     */
    public function setKey(string $key): void
    {
        if (\strlen($key) < 8 && \strlen($key) > 256) {
            throw new \Exception("Key must be between 8 and 256 characters");
        }
        $this->key = $key;
    }

    /**
     * getKey()
     * Return the encryption key
     * 
     * @return string
     */
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * setMethod()
     * Set the encryption method
     * 
     * @param string $method
     * 
     * @return void
     */
    public function setMethod(string $method): void
    {
        $method = \strtolower($method);
        if (!\in_array($method, \openssl_get_cipher_methods(false))) {
            throw new \Exception("Method not found");
        }
        $this->method = $method;
    }

    /**
     * getMethod()
     * Return the encryption method
     * 
     * @return string
     */
    public function getMethod(): string
    {
        return $this->method;
    }

    /**
     * doGenerateSalts()
     * Generate a list of salts
     *
     * @param int $count
     * @param int $length
     * 
     * @return array
     */
    private function doGenerateSalts(int $count = 64, int $length = 8): array
    {
        $salts = array();
        for ($i = 0; $i < $count; $i++) {
            \array_push($salts, $this->doGenerateSalt($length));
        }
        return $salts;
    }

    /**
     * doGenerateSalt()
     * Generate a salt
     * 
     * NOTE: The generated values ​​are not to be duplicated.
     * 
     * @param int $length
     * 
     * @return string
     */
    private function doGenerateSalt(int $length = 8): array
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

    /**
     * doAddSaltToEncryption()
     * Add a salt on the encrypted string
     * 
     * @param string $string
     * @param ?int &$length
     * 
     * @return string
     */
    private function doAddSaltToEncryption(string $string, ?int &$length = null): string
    {
        $id = \array_rand($this->salts);
        $enc = \base64_encode(\str_pad($id, \strlen(self::SALT_COUNT) + 1, 0, STR_PAD_LEFT));
        $enc = \strtr($enc, '+/', '-.');
        $enc = \rtrim($enc, '=');
        $enc = \strrev($enc);
        $length = \strlen($enc);
        return $enc . \str_replace(\str_split($this->salts[$id][0]), \str_split($this->salts[$id][1]), $string);
    }

    /**
     * doRemoveSaltFromDecryption()
     * Remove the salt from the decryption
     * 
     * @param string $string
     * @param int $length
     * 
     * @return string
     */
    private function doRemoveSaltFromDecryption(string $string, int $length): string
    {
        $dec = \substr($string, 0, $length);
        $dec = \strrev($dec);
        $dec = \strtr($dec, '-.', '+/');
        if (!($id = \base64_decode($dec))) {
            throw new \Exception("The salt is invalid.");
        }
        if (!\is_numeric($id = \intval($id))) {
            throw new \Exception("Invalid salt id");
        }
        return \str_replace(\str_split($this->salts[$id][1]), \str_split($this->salts[$id][0]), \substr($string, $length));
    }

    /**
     * encrypt()
     * Encrypt a string
     * 
     * @param string $string
     * 
     * @return string
     */
    public function encrypt(string $str): string
    {
        $iv = $this->getRNGProvider()->getRandomBytes(self::IV_LENGTH);
        if (!$this->getRNGProvider()->isCryptographicallySecure()) {
            throw new \Exception("The RNG is not cryptographically secure");
        }
        $key = \hash($this->hash, $this->key, true);
        if (!($enc = \openssl_encrypt($str, $this->method, $key, 0, $iv))) {
            throw new \Exception("Error encrypting string");
        }
        $enc = \strtr($enc, '+/', '-.');
        $enc = \rtrim($enc, '=');
        $iv = \bin2hex($iv);
        $iv = \base64_encode($iv);
        $iv = \strtr($iv, '+/', '-.');
        $iv = \rtrim($iv, '=');
        $str = $iv . $enc;
        if ($this->useSalt) {
            $str = $this->doAddSaltToEncryption($str);
        }
        return $str;
    }

    /**
     * decrypt()
     * Decrypt a string
     * 
     * @param string $string
     * 
     * @return string
     */
    public function decrypt(string $str): ?string
    {
        if ($this->useSalt) {
            if (\strlen($str) < $this->saltLength) {
                return null;
            }
            if (\is_null($this->saltLength)) {
                $this->doAddSaltToEncryption($str, $this->saltLength);
            }
            $str = $this->doRemoveSaltFromDecryption($str, $this->saltLength);
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
