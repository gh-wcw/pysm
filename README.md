## 采用纯原生Python代码，不借助任何第三方依赖，实现国密SM4、SM3、SM2算法。
### 对外方法均采用类方法调用模式：
#### SM4加密：
> 类方法调用：SM4.encrypt(key, plaintext, key_type)  
> 参数说明：key 秘钥，plaintext 待加密原文，key_type 密钥类型(HEXSTR-十六进制字符，HEXBYTE-十六进制字节)  
> 返回：十六进制字符串
#### SM4解密：
> 类方法调用：SM4.decrypt(key, ciphertext, key_type)
> 参数说明：key 秘钥，ciphertext 待解密密文，key_type 密钥类型(HEXSTR-十六进制字符，HEXBYTE-十六进制字节)
> 返回：原文普通字符串
#### SM3哈希：
> 类方法调用：SM3.hash(value)
> 参数说明：value 待哈希处理的原文
> 返回：十六进制字符串
#### SM2加密：
> 类方法调用：SM2.encrypt(pub_key, plaintext)
> 参数说明：pub_key 公钥，plaintext 待加密原文
> 返回：十六进制字符串
#### SM2解密：
> 类方法调用：SM2.decrypt(pri_key, ciphertext)
> 参数说明：pri_key 私钥，ciphertext 待解密密文
> 返回：原文普通字符串
#### SM2加密(Base64)：
> 类方法调用：SM2.encryptToBase64(pub_key_hex, plain_text)
> 参数说明：pub_key_hex 公钥，plain_text 待加密原文
> 返回：Base64字符串(不是字节)
#### SM2解密(Base64)：
> 类方法调用：SM2.decryptFromBase64(pri_key_hex, cipher_text)
> 参数说明：pri_key_hex 私钥，cipher_text 待解密密文Base64字符串
> 返回：原文普通字符串
#### SM2签名(DER格式)：
> 类方法调用：SM2.sign(pri_key, pub_key, value)
> 参数说明：pri_key 私钥，pub_key 公钥，value 待签名的原文
> 返回：十六进制字符(DER格式)
#### SM2验签(DER格式)：
> 类方法调用：SM2.verify(pub_key, sign, value)
> 参数说明：pub_key 公钥，sign 签名十六进制字符(DER格式)，value 原文
> 返回：验签结果(1通过，0不通过)
