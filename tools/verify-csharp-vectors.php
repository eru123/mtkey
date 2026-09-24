<?php
/**
 * Reverse cross-check: MTkey (C#) encrypts, the real PHP library decrypts.
 * Reads lines of "mode|key_ascii|password|ciphertext_hex" from stdin, where
 * mode is 'key' or 'password'. Each must decrypt to the known plaintext
 * below. Exit 0 = all good.
 */

$libDir = $argv[1] ?? dirname(__DIR__) . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'defuse-ref' . DIRECTORY_SEPARATOR . 'src';
spl_autoload_register(function (string $class) use ($libDir): void {
    $prefix = 'Defuse\\Crypto\\';
    if (str_starts_with($class, $prefix)) {
        $file = $libDir . DIRECTORY_SEPARATOR . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($file)) require $file;
    }
});

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;

$plaintext = 'cross language handshake';
$fail = 0;
$n = 0;
foreach (file('php://stdin', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
    [$mode, $keyAscii, $password, $ciphertext] = explode('|', $line);
    $n++;
    try {
        if ($mode === 'key') {
            $key = Key::loadFromAsciiSafeString($keyAscii);
            $result = Crypto::decrypt($ciphertext, $key);
        } else {
            $result = Crypto::decryptWithPassword($ciphertext, $password);
        }
        if ($result !== $plaintext) { fwrite(STDERR, "line $n: wrong plaintext\n"); $fail++; }
    } catch (Throwable $e) {
        fwrite(STDERR, "line $n ($mode): {$e->getMessage()}\n");
        $fail++;
    }
}
echo $fail === 0 ? "OK: $n C# ciphertexts fully interoperate with PHP\n" : "FAILURES: $fail of $n\n";
exit($fail === 0 ? 0 : 1);
