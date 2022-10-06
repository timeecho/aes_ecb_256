<?php
$cipher ="AES-256-ECB";
$private_key = "xxxxxxxxxxxxxxxxxxx"; // 商户密钥
$key=md5($private_key);

// 待加密字符串，标准json字符串。注意：提单金额不要用string
$plaintext =  "{\"amount\":200.00,\"channelnum\":\"10098\",\"noticetag\":\"OK\",\"noticeurl\":\"http://xxx.xxx.xx.xxx\",\"ordernum\":\"OR16645888802\",\"payok2ur_bak\":\"http://xx.xx.xx\"}";

$chiperRaw1 = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA);
$ciphertext = trim(base64_encode($chiperRaw1));
echo $ciphertext;

echo "\r\n=======================\r\n";

//解密
$chiperRaw2 = base64_decode($ciphertext);
$originalPlaintext = openssl_decrypt($chiperRaw2, $cipher, $key, OPENSSL_RAW_DATA);
echo $originalPlaintext;

?>