<?php
/**
 * Generates cross-language test vectors for MTKey's mcrypt support using a
 * REAL PHP 5.6 mcrypt extension, the same extension legacy PHP applications
 * encrypted with (Laravel 3/4, Magento 1, old phpMyAdmin, and a decade of
 * bespoke app code).
 *
 * Run it inside a container that still has mcrypt, e.g. one built from
 * tools/mcrypt-php56.Dockerfile:
 *
 *   docker run --rm -v "$PWD:/work" -w /work mcrypt-php56 \
 *     php tools/gen-mcrypt-vectors.php > tests/mcrypt-vectors.json
 *
 * Written in PHP 5 syntax on purpose; do not modernize it.
 */

if (!extension_loaded('mcrypt')) {
    fwrite(STDERR, "the mcrypt extension is not loaded\n");
    exit(1);
}

$keys = array(
    'rijndael-128' => array(
        '32' => '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        '16' => '2b7e151628aed2a6abf7158809cf4f3c',
    ),
    'rijndael-192' => array(
        '24' => '000102030405060708090a0b0c0d0e0f1011121314151617',
    ),
    'rijndael-256' => array(
        '32' => '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    ),
    'blowfish' => array(
        '16' => '626c6f77666973686b65793132333435363738', // 'blowfishkey12345678'
        '4'  => '74657374', // 'test' - blowfish takes short keys as-is
    ),
    'des' => array(
        '8' => '133457799bbcdff1',
    ),
    '3des' => array(
        '24' => '0123456789abcdef23456789abcdef01fedcba9876543210',
    ),
    'arcfour' => array(
        '16' => '0123456789abcdef0123456789abcdef',
    ),
);

$algorithms = array(
    'rijndael-128' => MCRYPT_RIJNDAEL_128,
    'rijndael-192' => MCRYPT_RIJNDAEL_192,
    'rijndael-256' => MCRYPT_RIJNDAEL_256,
    'blowfish'     => MCRYPT_BLOWFISH,
    'des'          => MCRYPT_DES,
    '3des'         => MCRYPT_3DES,
    'arcfour'      => MCRYPT_ARCFOUR,
);

// hex-encoded plaintexts: 1 byte (heavy zero padding), exactly one block of
// AES (no padding needed), a longer mixed string, and a UTF-8 multibyte one.
$plaintexts = array(
    'tiny'   => '58',                                           // 'X'
    'block'  => '30313233343536373839616263646566',             // '0123456789abcdef'
    'long'   => '54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67',
    'utf8'   => '726f756e6474726970206d6520f09f8eb2',           // 'roundtrip me <dice>'
);

$ivs = array(
    'rijndael-128' => 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    'rijndael-192' => 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7',
    'rijndael-256' => 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    'blowfish'     => 'f0f1f2f3f4f5f6f7',
    'des'          => 'f0f1f2f3f4f5f6f7',
    '3des'         => 'f0f1f2f3f4f5f6f7',
    'arcfour'      => '',
);

$modes = array('cbc', 'ecb', 'nofb', 'ncfb', 'stream');

$cases = array();
$index = 0;

foreach ($algorithms as $algoName => $algoConst) {
    // arcfour is a stream cipher; asking it for a block size fails loudly.
    $blockSize = $algoName === 'arcfour' ? 1 : mcrypt_get_block_size($algoConst, 'cbc');
    foreach ($keys[$algoName] as $keyBitsLabel => $keyHex) {
        $key = pack('H*', $keyHex);
        foreach ($modes as $mode) {
            if ($mode === 'stream' && $algoName !== 'arcfour') continue;
            if ($mode !== 'stream' && $algoName === 'arcfour') continue;
            if ($mode === 'stream' || $mode === 'ecb') {
                $iv = '';
                $ivHex = '';
            } else {
                $ivHex = $ivs[$algoName];
                $iv = pack('H*', $ivHex);
            }
            foreach ($plaintexts as $ptName => $ptHex) {
                // ECB keeps every case independent; for the others one
                // plaintext per algo/key/mode would be enough, but a full
                // matrix is cheap and catches padding edge cases everywhere.
                $pt = pack('H*', $ptHex);
                $index++;
                $id = sprintf('%03d-%s-%s-k%s-%s', $index, $algoName, $mode, $keyBitsLabel, $ptName);
                $ct = mcrypt_encrypt($algoConst, $key, $pt, $mode, $iv);
                $back = mcrypt_decrypt($algoConst, $key, $ct, $mode, $iv);
                $cases[$id] = array(
                    'algorithm' => $algoName,
                    'mode' => $mode,
                    'key_hex' => $keyHex,
                    'iv_hex' => $ivHex,
                    'plaintext_hex' => $ptHex,
                    'ciphertext_hex' => bin2hex($ct),
                    // mcrypt_decrypt returns the zero padding; recorded so the
                    // port can prove it strips exactly what mcrypt left in.
                    'decrypted_hex' => bin2hex($back),
                    'block_size' => $blockSize,
                );
            }
        }
    }
}

// One deterministic ECB case for rijndael-192 with the NIST-style zero key,
// handy when reasoning about the 192-bit block schedule.
$cases['rijndael-256-ecb-zero'] = array(
    'algorithm' => 'rijndael-256',
    'mode' => 'ecb',
    'key_hex' => str_repeat('00', 32),
    'iv_hex' => '',
    'plaintext_hex' => str_repeat('00', 32),
    'ciphertext_hex' => bin2hex(mcrypt_encrypt(
        MCRYPT_RIJNDAEL_256, str_repeat("\0", 32), str_repeat("\0", 32), 'ecb')),
    'decrypted_hex' => '',
    'block_size' => 32,
);

// A Laravel 4.2-style payload assembled exactly the way
// Illuminate\Encryption\Encrypter did: serialize() -> PKCS7 pad (16) ->
// mcrypt rijndael-128 cbc -> hmac-sha256 over base64(iv).base64(ct) with the
// raw app key -> base64(json). Real serialize/mcrypt/hash_hmac calls, so
// only the glue is ours - which is exactly the part worth testing.
$lvKey = '0123456789abcdef0123456789abcdef';
$lvIv = pack('H*', 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
$lvPlain = 'hello from laravel four';
$lvSer = serialize($lvPlain);
$lvPad = 16 - (strlen($lvSer) % 16);
$lvPadded = $lvSer . str_repeat(chr($lvPad), $lvPad);
$lvCt = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $lvKey, $lvPadded, 'cbc', $lvIv);
$lvIvB = base64_encode($lvIv);
$lvValB = base64_encode($lvCt);
$lvMac = hash_hmac('sha256', $lvIvB . $lvValB, $lvKey);
$cases['laravel4_payload'] = array(
    'algorithm' => 'rijndael-128',
    'mode' => 'cbc',
    'key_hex' => bin2hex($lvKey),
    'iv_hex' => bin2hex($lvIv),
    'plaintext_hex' => bin2hex($lvPlain),
    'serialized_hex' => bin2hex($lvSer),
    'ciphertext_hex' => bin2hex($lvCt),
    'mac' => $lvMac,
    'payload_b64' => base64_encode(json_encode(array('iv' => $lvIvB, 'value' => $lvValB, 'mac' => $lvMac))),
    'block_size' => 16,
);

echo json_encode($cases, JSON_PRETTY_PRINT);
echo "\n";
