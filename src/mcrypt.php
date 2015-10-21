<?php

/*
 * 对称性加密解密
 * 根据PHP官方代码修改
 * http://php.net/manual/zh/function.mcrypt-encrypt.php
 *
 * @version 0.1
 * @since 2015-10-21
 * @author Ken <695093513@qq.com>
 */

namespace normalApi\mcrypt;

class mcryptModel {

    /**
     * 加密
     * @param string $plaintext
     * @return string
     */
    public function encode($plaintext) {
        # --- 加密 ---
        # 密钥应该是随机的二进制数据，
        # 开始使用 scrypt, bcrypt 或 PBKDF2 将一个字符串转换成一个密钥
        # 密钥是 16 进制字符串格式
        $key = pack('H*', "bcb04b7e103a0cd8b54763051cef08bc55abe029fdebae5e1d417e2ffb2a00a3");

        # 显示 AES-128, 192, 256 对应的密钥长度：
        #16，24，32 字节。
        #$key_size = strlen($key);
        #echo "Key size: " . $key_size . "\n";
        #
        #
        # 为 CBC 模式创建随机的初始向量
        $iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);


        # 创建和 AES 兼容的密文（Rijndael 分组大小 = 128）
        # 仅适用于编码后的输入不是以 00h 结尾的
        # （因为默认是使用 0 来补齐数据）
        $ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $plaintext, MCRYPT_MODE_CBC, $iv);

        # 将初始向量附加在密文之后，以供解密时使用
        $ciphertext = $iv . $ciphertext;

        # 对密文进行 base64 编码
        $ciphertext_base64 = base64_encode($ciphertext);

        return $ciphertext_base64;
    }

    /**
     * 解密
     * @param string $ciphertext_base64
     * @return string
     */
    public function decode($ciphertext_base64) {
        # === 警告 ===
        # 密文并未进行完整性和可信度保护，
        # 所以可能遭受 Padding Oracle 攻击。
        # --- 解密 ---
        $key = pack('H*', "bcb04b7e103a0cd8b54763051cef08bc55abe029fdebae5e1d417e2ffb2a00a3");

        $ciphertext_dec = base64_decode($ciphertext_base64);

        # 初始向量大小，可以通过 mcrypt_get_iv_size() 来获得
        $iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $iv_dec = substr($ciphertext_dec, 0, $iv_size);

        # 获取除初始向量外的密文
        $ciphertext_dec = substr($ciphertext_dec, $iv_size);

        # 可能需要从明文末尾移除 0
        $plaintext_dec = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $ciphertext_dec, MCRYPT_MODE_CBC, $iv_dec);

        return $plaintext_dec;
    }

}
