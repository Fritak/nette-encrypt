<?php
namespace Encrypt;

use Nette\Object;
use Encrypt\EncryptException;

/**
 * 
 * This is OLD version, insecure.
 * 
 * @property-read string $packKey Binary string containing $key.
 * @property-read string $hashMac 
 * @property-read string $randomKey  
 * 
 * @deprecated since version 1.0
 */
Class EncryptM extends Object
{
    private $storedKey;
    private $data;
    
    public function setKey($key)
    {
        if(ctype_xdigit($key) && strlen($key) === 64)
        {
            $this->storedKey = $key;
        }
        else
        {
            throw new EncryptException('The key is invalid.', 1);
        }
    }
    
    public function getRandomKey()
    {
        return bin2hex(openssl_random_pseudo_bytes(128));
    }
    
    public function getKey()
    {
        if(empty($this->storedKey))
        {
            throw new EncryptException('The key cannot be empty.', 2);
        }
        
        return $this->storedKey;
    }
    
    public function getHashMac()
    {
        if(empty($this->data))
        {
            throw new EncryptException('Data cannot be empty.', 3);
        }
        
        return hash_hmac('sha256', $this->data, substr($this->key, -32));
    }
    
    public function getPackKey()
    {
        return pack('H*', $this->key);
    }
    
    
    /**
     * 
     * @param string $dataToEncrypt Data to encrypt.
     * @return string
     */
    public function encrypt($dataToEncrypt)
    {
        $this->data = serialize($dataToEncrypt);

        $iv        = \mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC), MCRYPT_DEV_URANDOM);
        $encrypted = \mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->packKey, $this->data . $this->hashMac, MCRYPT_MODE_CBC, $iv);

        return base64_encode($encrypted) . '|' . base64_encode($iv);
    }
    
    /**
     * 
     * @param string $dataToDecrypt Data to decrypt.
     * @return boolean
     */
    public function decrypt($dataToDecrypt)
    {
        $data = explode('|', $dataToDecrypt);
        
        if(count($data) <> 2)
        { 
            throw new EncryptException('Data are invalid.', 4);
        }
        
        $decoded = base64_decode($data[0]);
        $iv      = base64_decode($data[1]);
        $ivSize  = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        
        if(strlen($iv) !== $ivSize)
        { 
            throw new EncryptException('The iv (initialization vector) is invalid.', 5);
        }
        
        $decrypted = trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->packKey, $decoded, MCRYPT_MODE_CBC, $iv));
        $decryptedHasMac = substr($decrypted, -64);
        $this->data      = substr($decrypted, 0, -64);
        
        if($this->hashMac !== $decryptedHasMac)
        {
            throw new EncryptException('CRC check has failed (wrong key?).', 6);
        }

        return unserialize($this->data);
    }
}
