<?php
namespace Encrypt;

use Nette\Object;
use Encrypt\EncryptException;

/**
 * This class is only functional when PHP is compiled with OpenSSL 0.9.8+.
 * 
 * @property-read string $key Key
 * @property-read string $iv Initialization Vector
 * @property-read string $randomKey
 */
Class Encrypt extends Object
{
    const REQUIRED_KEY_LENGTH = [16, 24, 32];
    const OPENSSL_OPTIONS = OPENSSL_RAW_DATA;
    
    private $storedKey;
    private $storedIv;
    private $aesMode;
    
    public function __construct($key = null, $iv = null)
    {
        if(!empty($key))
        {
            $this->key = $key;
        }
        
        if(!empty($iv))
        {
            $this->iv = $iv;
        }
    }
    
    public function setKey($key) 
    {
        if (!is_string($key)) 
        {
            throw new \InvalidArgumentException("Key must be a valid string.");
        }
        
        $strLen = $this->calculateStringLen($key);

        if (!in_array($strLen, self::REQUIRED_KEY_LENGTH)) 
        {
            throw new \InvalidArgumentException("Key length must be 16, 24, or 32 bytes.");
        }

        // Set the openssl mode string by key bit size
        $this->aesMode = 'aes-' . (8 * $strLen) . '-cbc';
        $this->storedKey = $key;
    }
    
    public function setIv($iv) 
    {
        if (!is_string($iv)) 
        {
            throw new \InvalidArgumentException("IV must be a valid string.");
        }
        if ($this->calculateStringLen($iv) != 16) 
        {
            throw new \InvalidArgumentException("IV length must be 16 bytes.");
        }
        
        $this->storedIv = $iv;
    }
    
    public function getRandomKey()
    {
        return bin2hex(openssl_random_pseudo_bytes(16));
    }
    
    public function getKey()
    {
        if(empty($this->storedKey))
        {
            throw new EncryptException('The key cannot be empty. Call setKey() prior to usage.');
        }
        
        return $this->storedKey;
    }
    
    public function getIv()
    {
        if(empty($this->storedIv))
        {
            throw new EncryptException('The IV cannot be empty. Call setIv() prior to usage.');
        }
        
        return $this->storedIv;
    }
    
    
    /**
     * 
     * @param string $data Data to encrypt.
     * @return string
     */
    public function encrypt($data)
    {
        return openssl_encrypt($data, $this->aesMode, $this->key, self::OPENSSL_OPTIONS, $this->iv);
    }
    
    /**
     * 
     * @param string $cipherData Data to decrypt.
     * @return boolean
     */
    public function decrypt($cipherData)
    {
        return openssl_decrypt($cipherData, $this->aesMode, $this->key, self::OPENSSL_OPTIONS, $this->iv);
    }
    
    /**
     * 
     * @param string $key
     * @return int Length
     * @throws \EncryptException
     */
    private function calculateStringLen($key) 
    {
        if (\function_exists('mb_strlen')) 
        {
            $length = \mb_strlen($key, '8bit');
            
            if ($length === FALSE) 
            {
                throw new \EncryptException("Invalid encoding.");
            }
            
            return $length;
        } 
        else 
        {
            return \strlen($key);
        }
    }
}
