import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class ecb {

    public static void main(String[] argv) throws Exception {
        // privateKey: 商户私钥
        String privateKey = "XXXXXXXXXXXXXXXXXXX";
        System.out.println("========md5 key========");
        System.out.println(getMd5(privateKey));
        System.out.println("========md5 key========");

        // testBase64();

        // {"amount":"200.00","channelnum":"10098","noticetag":"OK","noticeurl":"http://xxxxxxxxxxxxywap","ordernum":"OR1664524214000002","payok2ur_bak":"http://xxxxxxxxxxx.html"}

        // 请构建结构体对象，自行转json标准字符串，下面是测试结构
        // 参数说明请看 api 文档
        // String jsonstr = "{\"amount\":\"200.00\",\"channelnum\":\"10098\",\"noticetag\":\"OK\",\"noticeurl\":\"http://xxxxxxxxxxxxywap\",\"ordernum\":\"OR1664524214000002\",\"payok2ur_bak\":\"http://xxxxxxxxxxx.html\"}";
        
        String jsonstr =  "{\"amount\":200.00,\"channelnum\":\"10098\",\"noticetag\":\"OK\",\"noticeurl\":\"http://xxx.xxx.xx.xxx\",\"ordernum\":\"OR16645888802\",\"payok2ur_bak\":\"http://xx.xx.xx\"}";
        

        String postData = genPushOrder(privateKey, jsonstr);
        System.out.println(new String("================base64编码输出================"));
        System.out.println(postData);

        // 构建 payload 对象
        // {
        // Token: Privatetoken, //Privatetoken对象
        // Data: postData,
        // }

        // 将payload转标准json字符串进行提单请求即可

        // ==============================================

        // 逆向解密操作：
        String originalData = analyzeString(privateKey, postData);
        System.out.println(originalData);
    }

    private static void testBase64() {
        // String encodedString = ...
        // Base64.getEncoder().encodeToString(str2.getBytes());
        // System.out.println(encodedString);

        // base64 编码
        String privateKey = "64EAB68AF9534525B4673EC228E804FD3680054EC15F48779D50F129635D0391";
        byte[] encodeBytes = Base64.getEncoder().encode(privateKey.getBytes());
        System.out.println(new String(encodeBytes));

        // base64 解码
        String base64str = "NjRFQUI2OEFGOTUzNDUyNUI0NjczRUMyMjhFODA0RkQzNjgwMDU0RUMxNUY0ODc3OUQ1MEYxMjk2MzVEMDM5MQ==";
        byte[] decodedBytes = Base64.getDecoder().decode(base64str);
        String decodedString = new String(decodedBytes);
        System.out.println(decodedString);
    }

    // 加密对象
    private static String genPushOrder(String privateKey, String jsonstr) throws Exception {
        byte[] result = perfromEncryption(jsonstr, getMd5(privateKey));
        System.out.println(new String("================加密输出================"));
        System.out.println(new String(result));

        byte[] genResult = Base64.getEncoder().encode(result);
        String postData = new String(genResult);
        return postData;
    }

    // 解密字符
    private static String analyzeString(String privateKey, String postData) throws Exception {
        byte[] decodedBytes = Base64.getDecoder().decode(postData);        
        System.out.println(new String("================base64解码输出================"));
        System.out.println(new String(decodedBytes));

        byte[] decodeAECBytes = perfromDecryption(decodedBytes, getMd5(privateKey));
        System.out.println(new String("================解密输出================"));
        String result = new String(decodeAECBytes);
        return result;
    }

    public static byte[] perfromEncryption(String targeString, String md5key) throws Exception {
        SecretKeySpec myKey = new SecretKeySpec(md5key.getBytes("UTF-8"), "AES");
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, myKey);
        byte[] text = targeString.getBytes("UTF-8"); // 也可以直接传递byte[]进来，这里少转一道
        byte[] textEncrypted = c.doFinal(text);
        return (textEncrypted);
    }

    public static byte[] perfromDecryption(byte[] text, String md5key) throws Exception {
        SecretKeySpec myKey = new SecretKeySpec(md5key.getBytes("UTF-8"), "AES");
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, myKey);
        byte[] textDecrypted = c.doFinal(text);
        return (textDecrypted);
    }

    public static String getMd5(String input) {
        try {

            // Static getInstance method is called with hashing MD5
            MessageDigest md = MessageDigest.getInstance("MD5");

            // digest() method is called to calculate message digest
            // of an input digest() return array of byte
            byte[] messageDigest = md.digest(input.getBytes());

            // Convert byte array into signum representation
            BigInteger no = new BigInteger(1, messageDigest);

            // Convert message digest into hex value
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        }

        // For specifying wrong message digest algorithms
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
