<?php
/**
 * Generates cross-language test vectors for MTKey using the REAL
 * defuse/php-encryption library, and verifies a few known-answer constants
 * (like the jwt.io HS256 token) with PHP's own crypto.
 *
 * Usage: php tools/gen-vectors.php [path-to-library-src] > tests/Mtkey.Tests/vectors.json
 * Defaults to ../defuse-ref/src relative to this script.
 */

$libDir = $argv[1] ?? dirname(__DIR__) . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'defuse-ref' . DIRECTORY_SEPARATOR . 'src';
if (!is_dir($libDir)) {
    fwrite(STDERR, "defuse/php-encryption source not found at $libDir\n");
    exit(1);
}

spl_autoload_register(function (string $class) use ($libDir): void {
    $prefix = 'Defuse\\Crypto\\';
    if (str_starts_with($class, $prefix)) {
        $file = $libDir . DIRECTORY_SEPARATOR . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($file)) {
            require $file;
        }
    }
});

use Defuse\Crypto\Core;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Defuse\Crypto\KeyProtectedByPassword;

function b64url(string $raw): string {
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}

// Guard the famous jwt.io HS256 constant against my own memory: PHP computes
// the signature itself and refuses to emit vectors if it does not match.
{
    $h = '{"alg":"HS256","typ":"JWT"}';
    $p = '{"sub":"1234567890","name":"John Doe","iat":1516239022}';
    $expectedSig = 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    $actualSig = b64url(hash_hmac('sha256', b64url($h) . '.' . b64url($p), 'your-256-bit-secret', true));
    if ($actualSig !== $expectedSig) {
        fwrite(STDERR, "jwt.io constant mismatch: $actualSig\n");
        exit(2);
    }
}

$out = [];

// ------------------------------------------------- v2 key mode, real library
$plaintext = 'The quick brown fox jumps over the lazy dog. ';
$key = Key::createNewRandomKey();
$keyAscii = $key->saveToAsciiSafeString();
$out['v2_key'] = [
    'key_ascii' => $keyAscii,
    'plaintext' => $plaintext,
    'ciphertext_hex' => Crypto::encrypt($plaintext, $key),
];

// --------------------------------------------- v2 password mode, real library
$password = 'correct horse battery staple';
$out['v2_password'] = [
    'password' => $password,
    'plaintext' => $plaintext,
    'ciphertext_hex' => Crypto::encryptWithPassword($plaintext, $password),
];

// --------------------------------------- v2 fixed salt/iv KAT (both algos)
function defuseV2Kat(string $rawKeyHex, string $saltHex, string $ivHex, string $plaintext): string {
    $rawKey = hex2bin($rawKeyHex);
    $salt = hex2bin($saltHex);
    $iv = hex2bin($ivHex);
    $akey = Core::HKDF('sha256', $rawKey, Core::KEY_BYTE_SIZE, Core::AUTHENTICATION_INFO_STRING, $salt);
    $ekey = Core::HKDF('sha256', $rawKey, Core::KEY_BYTE_SIZE, Core::ENCRYPTION_INFO_STRING, $salt);
    $ct = openssl_encrypt($plaintext, Core::CIPHER_METHOD, $ekey, OPENSSL_RAW_DATA, $iv);
    $body = Core::CURRENT_VERSION . $salt . $iv . $ct;
    $mac = hash_hmac(Core::HASH_FUNCTION_NAME, $body, $akey, true);
    return bin2hex($body . $mac);
}

$fixedKeyHex = str_repeat('ab', 32);
$fixedSaltHex = str_repeat('11', 32);
$fixedIvHex = '000102030405060708090a0b0c0d0e0f';
$out['v2_kat'] = [
    'key_hex' => $fixedKeyHex,
    'salt_hex' => $fixedSaltHex,
    'iv_hex' => $fixedIvHex,
    'plaintext' => 'deterministic kat',
    'ciphertext_hex' => defuseV2Kat($fixedKeyHex, $fixedSaltHex, $fixedIvHex, 'deterministic kat'),
];

// Password mode with fixed salt/iv: prehash, PBKDF2, HKDF, then the same body.
{
    $pw = 'kat password';
    $salt = hex2bin($fixedSaltHex);
    $iv = hex2bin($fixedIvHex);
    $pt = 'password kat';
    $prehash = hash(Core::HASH_FUNCTION_NAME, $pw, true);
    $prekey = Core::pbkdf2(Core::HASH_FUNCTION_NAME, $prehash, $salt, 100000, Core::KEY_BYTE_SIZE, true);
    $akey = Core::HKDF('sha256', $prekey, 32, Core::AUTHENTICATION_INFO_STRING, $salt);
    $ekey = Core::HKDF('sha256', $prekey, 32, Core::ENCRYPTION_INFO_STRING, $salt);
    $ct = openssl_encrypt($pt, Core::CIPHER_METHOD, $ekey, OPENSSL_RAW_DATA, $iv);
    $body = Core::CURRENT_VERSION . $salt . $iv . $ct;
    $mac = hash_hmac(Core::HASH_FUNCTION_NAME, $body, $akey, true);
    $out['v2_password_kat'] = [
        'password' => $pw,
        'salt_hex' => $fixedSaltHex,
        'iv_hex' => $fixedIvHex,
        'plaintext' => $pt,
        'ciphertext_hex' => bin2hex($body . $mac),
    ];
}

// ------------------------------------- password-protected key, real library
{
    $wrapPassword = 'wrap it up';
    $protected = KeyProtectedByPassword::createRandomPasswordProtectedKey($wrapPassword);
    $inner = $protected->unlockKey($wrapPassword);
    $out['key_wrap'] = [
        'password' => $wrapPassword,
        'protected_key_ascii' => $protected->saveToAsciiSafeString(),
        'inner_key_ascii' => $inner->saveToAsciiSafeString(),
    ];
}

// ------------------------------------------------- legacy v1, manual build
{
    $legacyKey = hex2bin(str_repeat('2a', 16));
    $legacyIv = hex2bin('101112131415161718191a1b1c1d1e1f');
    $legacyPt = 'old times';
    $akey = Core::HKDF('sha256', $legacyKey, Core::LEGACY_KEY_BYTE_SIZE, Core::LEGACY_AUTHENTICATION_INFO_STRING, null);
    $ekey = Core::HKDF('sha256', $legacyKey, Core::LEGACY_KEY_BYTE_SIZE, Core::LEGACY_ENCRYPTION_INFO_STRING, null);
    $ct = openssl_encrypt($legacyPt, Core::LEGACY_CIPHER_METHOD, $ekey, OPENSSL_RAW_DATA, $legacyIv);
    $message = $legacyIv . $ct;
    $mac = hash_hmac('sha256', $message, $akey, true);
    $out['legacy_kat'] = [
        'key_hex' => bin2hex($legacyKey),
        'plaintext' => $legacyPt,
        'ciphertext_hex' => bin2hex($mac . $message),
    ];
}

echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), PHP_EOL;
