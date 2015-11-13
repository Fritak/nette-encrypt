# nette-encrypt

## Usage

```php
// Set your key and iv
$key = '2da3a09b19409f999c07cdf70b0267f5';
$iv  = 'dcd66c321930793f';

$encrypt = new \Encrypt\Encrypt($key, $iv);

// or you can set them later on
$encrypt->key = $key;
$encrypt->iv  = $iv;

// Encrypt with encrypt()
$data = $encrypt->encrypt('Please help me.');

// Decrypt with decrypt()
print $encrypt->encrypt($data);
```
