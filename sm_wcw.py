# !/usr/bin/env python
# -*- coding:utf-8 -*-
"""
Creator: 汪春旺
Date: 2026/05/26
Description: 采用纯原生Python代码，不借助任何第三方依赖，实现国密SM4、SM3、SM2算法。
    对外方法均采用类方法调用模式：
    ---------------------------------------------------------------------------------------------------
      SM4加密：
        类方法调用：SM4.encrypt(key, plaintext, key_type)
        参数说明：key 秘钥，plaintext 待加密原文，key_type 密钥类型(HEXSTR-十六进制字符，HEXBYTE-十六进制字节)
        返回：十六进制字符串
      SM4解密：
        类方法调用：SM4.decrypt(key, ciphertext, key_type)
        参数说明：key 秘钥，ciphertext 待解密密文，key_type 密钥类型(HEXSTR-十六进制字符，HEXBYTE-十六进制字节)
        返回：原文普通字符串
    ---------------------------------------------------------------------------------------------------
      SM3哈希：
        类方法调用：SM3.hash(value)
        参数说明：value 待哈希处理的原文
        返回：十六进制字符串
    ---------------------------------------------------------------------------------------------------
      SM2加密：
        类方法调用：SM2.encrypt(pub_key, plaintext)
        参数说明：pub_key 公钥，plaintext 待加密原文
        返回：十六进制字符串
      SM2解密：
        类方法调用：SM2.decrypt(pri_key, ciphertext)
        参数说明：pri_key 私钥，ciphertext 待解密密文
        返回：原文普通字符串
    ---------------------------------------------------------------------------------------------------
      SM2加密(Base64)：
        类方法调用：SM2.encryptToBase64(pub_key_hex, plain_text)
        参数说明：pub_key_hex 公钥，plain_text 待加密原文
        返回：Base64字符串(不是字节)
      SM2解密(Base64)：
        类方法调用：SM2.decryptFromBase64(pri_key_hex, cipher_text)
        参数说明：pri_key_hex 私钥，cipher_text 待解密密文Base64字符串
        返回：原文普通字符串
    ---------------------------------------------------------------------------------------------------
      SM2签名(DER格式)：
        类方法调用：SM2.sign(pri_key, pub_key, value)
        参数说明：pri_key 私钥，pub_key 公钥，value 待签名的原文
        返回：十六进制字符(DER格式)
      SM2验签(DER格式)：
        类方法调用：SM2.verify(pub_key, sign, value)
        参数说明：pub_key 公钥，sign 签名十六进制字符(DER格式)，value 原文
        返回：验签结果(1通过，0不通过)
    ---------------------------------------------------------------------------------------------------
"""
import base64
import binascii
import random
import secrets
import struct
import sys


class SM4:
    # SM4 算法核心 S盒 (S-box)
    SBOX = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    ]

    # 系统参数 FK
    FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
    # 固定参数 CK
    CK = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    ]

    @staticmethod
    def _left_rotate(val, n):
        """循环左移"""
        return ((val << n) & 0xFFFFFFFF) | (val >> (32 - n))

    @staticmethod
    def _tau(a):
        """非线性变换 τ (S盒代换)"""
        return (SM4.SBOX[(a >> 24) & 0xFF] << 24) | \
            (SM4.SBOX[(a >> 16) & 0xFF] << 16) | \
            (SM4.SBOX[(a >> 8) & 0xFF] << 8) | \
            SM4.SBOX[a & 0xFF]

    @classmethod
    def _l_prime(cls, b):
        """密钥扩展中的线性变换 L'"""
        return b ^ (cls._left_rotate(b, 13)) ^ (cls._left_rotate(b, 23))

    @classmethod
    def _l(cls, b):
        """轮函数中的线性变换 L"""
        return b ^ (cls._left_rotate(b, 2)) ^ (cls._left_rotate(b, 10)) ^ \
            (cls._left_rotate(b, 18)) ^ (cls._left_rotate(b, 24))

    @classmethod
    def _t(cls, a):
        """合成置换 T"""
        return cls._l(cls._tau(a))

    @classmethod
    def key_expansion(cls, key_bytes):
        """生成32轮轮密钥"""
        mk = [int.from_bytes(key_bytes[i:i + 4], 'big') for i in range(0, 16, 4)]
        k = [mk[i] ^ cls.FK[i] for i in range(4)]
        rk = []
        for i in range(32):
            tmp = k[1] ^ k[2] ^ k[3] ^ cls.CK[i]
            k_next = k[0] ^ cls._l_prime(cls._tau(tmp))
            rk.append(k_next)
            k = k[1:] + [k_next]
        return rk

    @classmethod
    def encrypt_block(cls, block_bytes, rk):
        """单块(16字节)加密/解密核心运算"""
        x = [int.from_bytes(block_bytes[i:i + 4], 'big') for i in range(0, 16, 4)]
        for i in range(32):
            tmp = x[1] ^ x[2] ^ x[3] ^ rk[i]
            x_next = x[0] ^ cls._t(tmp)
            x = x[1:] + [x_next]
        # 反序输出
        return b''.join([x[3].to_bytes(4, 'big'), x[2].to_bytes(4, 'big'),
                         x[1].to_bytes(4, 'big'), x[0].to_bytes(4, 'big')])

    @staticmethod
    def pkcs7_pad(data):
        """PKCS7 填充"""
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    @classmethod
    def encrypt(cls, key, plaintext, key_type="HEXSTR"):
        """
        国密SM4 ECB模式加密，返回十六进制字符串
        :param key: 密钥
        :param plaintext: 待加密的字符串
        :param key_type: 密钥类型（HEXSTR-十六进制字符，HEXBYTE-十六进制字节）
        """
        if key_type == "HEXSTR":
            encrypt_key = bytes.fromhex(key)
        else:
            encrypt_key = key.encode()

        rk = cls.key_expansion(encrypt_key)

        # 将明文转为字节并进行 PKCS7 填充
        plain_bytes = str(plaintext).encode('utf-8')
        padded_data = cls.pkcs7_pad(plain_bytes)

        # 分块加密
        ciphertext = bytearray()
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i + 16]
            ciphertext.extend(cls.encrypt_block(block, rk))

        return ciphertext.hex()

    @classmethod
    def decrypt(cls, key, ciphertext, key_type="HEXSTR"):
        """
        国密SM4 ECB模式解密
        :param key: 密钥(十六进制字符或普通字符串)
        :param ciphertext: 待解密的十六进制字符串
        :param key_type: 密钥类型（HEXSTR-十六进制字符，HEXBYTE-十六进制字节）
        :return: 解密后的原始字符串
        """
        # 1. 处理密钥格式
        if key_type == "HEXSTR":
            encrypt_key = bytes.fromhex(key)
        else:
            encrypt_key = key.encode()

        # 2. 生成轮密钥并反转（SM4解密的核心：使用逆序的轮密钥进行运算）
        rk = cls.key_expansion(encrypt_key)
        rk.reverse()

        # 3. 将十六进制密文转为字节流
        cipher_bytes = bytes.fromhex(ciphertext)

        # 4. 分块解密（每16字节为一个分组）
        decrypted_padded = bytearray()
        for i in range(0, len(cipher_bytes), 16):
            block = cipher_bytes[i:i + 16]
            # 复用 encrypt_block 方法，传入反转后的轮密钥即可实现解密
            decrypted_padded.extend(cls.encrypt_block(block, rk))

        # 5. 去除 PKCS7 填充并返回原始字符串
        # 获取最后一个字节的值，即为填充的长度
        pad_len = decrypted_padded[-1]
        # 截取掉末尾的填充字节
        original_data = bytes(decrypted_padded[:-pad_len])

        return original_data.decode('utf-8')


class SM3:
    # 初始向量 IV
    IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
          0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]

    # 常量 T (前16轮为0x79CC4519，后48轮为0x7A879D8A)
    @staticmethod
    def _get_T(i):
        return 0x79CC4519 if 0 <= i < 16 else 0x7A879D8A

    @staticmethod
    def _left_rotate(val, n):
        """循环左移"""
        return ((val << n) & 0xFFFFFFFF) | (val >> (32 - n))

    @staticmethod
    def _xor_3(a, b, c):
        """三个数异或"""
        return a ^ b ^ c

    @staticmethod
    def _ff_j(X, Y, Z, j):
        """布尔函数 FF"""
        if 0 <= j < 16:
            return X ^ Y ^ Z
        else:
            return (X & Y) | (X & Z) | (Y & Z)

    @staticmethod
    def _gg_j(X, Y, Z, j):
        """布尔函数 GG"""
        if 0 <= j < 16:
            return X ^ Y ^ Z
        else:
            return (X & Y) | (~X & Z)

    @staticmethod
    def _p_0(X):
        """置换函数 P0"""
        return X ^ SM3._left_rotate(X, 9) ^ SM3._left_rotate(X, 17)

    @staticmethod
    def _p_1(X):
        """置换函数 P1"""
        return X ^ SM3._left_rotate(X, 15) ^ SM3._left_rotate(X, 23)

    @classmethod
    def _padding(cls, msg_bytes):
        """消息填充"""
        msg_len = len(msg_bytes) * 8
        msg_bytes += b'\x80'
        # 填充 0 直到长度满足 (len + 64) % 512 == 0
        while (len(msg_bytes) * 8 + 64) % 512 != 0:
            msg_bytes += b'\x00'
        # 附加原始消息长度（64位大端表示）
        msg_bytes += msg_len.to_bytes(8, 'big')
        return msg_bytes

    @classmethod
    def _msg_extend(cls, block):
        """消息扩展"""
        W = []
        # 将 512 位的分组拆分为 16 个 32 位字
        for i in range(16):
            W.append(int.from_bytes(block[i * 4:(i + 1) * 4], 'big'))

        # 扩展前 68 个字
        for j in range(16, 68):
            W.append(cls._p_1(W[j - 16] ^ W[j - 9] ^ cls._left_rotate(W[j - 3], 15)) ^
                     cls._left_rotate(W[j - 13], 7) ^ W[j - 6])

        # 生成用于压缩的后 64 个字
        W_prime = []
        for j in range(64):
            W_prime.append(W[j] ^ W[j + 4])

        return W, W_prime

    @classmethod
    def _compress(cls, V, block):
        """压缩函数"""
        W, W_prime = cls._msg_extend(block)
        A, B, C, D, E, F, G, H = V

        for j in range(64):
            SS1 = cls._left_rotate((cls._left_rotate(A, 12) + E + cls._left_rotate(cls._get_T(j), j % 32)) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ cls._left_rotate(A, 12)
            TT1 = (cls._ff_j(A, B, C, j) + D + SS2 + W_prime[j]) & 0xFFFFFFFF
            TT2 = (cls._gg_j(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = cls._left_rotate(B, 9)
            B = A
            A = TT1
            H = G
            G = cls._left_rotate(F, 19)
            F = E
            E = cls._p_0(TT2)

        return [A ^ V[0], B ^ V[1], C ^ V[2], D ^ V[3], E ^ V[4], F ^ V[5], G ^ V[6], H ^ V[7]]

    @classmethod
    def hash(cls, value):
        """
        国密SM3加密哈希算法，返回十六进制字符串
        :param value: 待加密的字符串或字节
        :return: 加密后的哈希值 (hex string)
        """
        # 统一处理输入为字节
        if isinstance(value, str):
            msg_bytes = value.encode('utf-8')
        elif isinstance(value, bytes):
            msg_bytes = value
        else:
            msg_bytes = str(value).encode('utf-8')

        # 1. 消息填充
        padded_msg = cls._padding(msg_bytes)

        # 2. 迭代压缩
        V = cls.IV.copy()
        # 按 64 字节 (512位) 分块处理
        for i in range(0, len(padded_msg), 64):
            block = padded_msg[i:i + 64]
            V = cls._compress(V, block)

        # 3. 输出结果
        result = ''.join([f"{v:08x}" for v in V])
        return result


class SM2:
    @classmethod
    def encrypt(cls, pub_key, plaintext):
        """
        国密SM2加密
        :param pub_key: sm2加密公钥(十六进制字符)
        :param plaintext: 待加密的字符串
        :return: sm2加密后的十六进制字符
        """

        def _inverse_mod(a, n):
            """Compute modular inverse of a modulo n using extended Euclidean algorithm."""
            if a == 0:
                return 0
            lm, hm = 1, 0
            low, high = a % n, n
            while low > 1:
                ratio = high // low
                nm, new = hm - lm * ratio, high - low * ratio
                lm, low, hm, high = nm, new, lm, low
            return lm % n

        def _point_add(P, Q, p, a):
            """Add two points P and Q on the elliptic curve."""
            if not P:
                return Q
            if not Q:
                return P

            Px, Py = P
            Qx, Qy = Q

            if Px == Qx and Py != Qy:
                return None  # Point at infinity

            if P == Q:
                # Point doubling: lambda = (3x^2 + a) / 2y
                lam = (3 * Px * Px + a) * _inverse_mod(2 * Py, p) % p
            else:
                # Point addition: lambda = (y2 - y1) / (x2 - x1)
                lam = (Qy - Py) * _inverse_mod(Qx - Px, p) % p

            x = (lam * lam - Px - Qx) % p
            y = (lam * (Px - x) - Py) % p
            return (x, y)

        def _scalar_mult(k, P, p, a):
            """Multiply point P by scalar k using double-and-add algorithm."""
            R = None
            N = P
            while k:
                if k & 1:
                    R = _point_add(R, N, p, a)
                N = _point_add(N, N, p, a)
                k >>= 1
            return R

        def _kdf(x, y, klen):
            """Key Derivation Function (KDF) as per GM/T 0003.4-2012."""
            ct = 1
            K = b''
            while len(K) < klen:
                # SM3 hash context
                hash_hex = SM3.hash(x.to_bytes(32, 'big') + y.to_bytes(32, 'big') + struct.pack('>I', ct))
                K += bytes(bytearray.fromhex(hash_hex))  # 为了兼容，用bytes(bytearray.fromhex())替换了bytes.fromhex()
                ct += 1
            return K[:klen]

        # print("SM2加密入参:", pub_key, plaintext)
        try:
            p = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16)
            a = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16)
            b = int('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16)
            n = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16)
            Gx = int('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7', 16)
            Gy = int('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', 16)

            # 1. Ensure public key is in correct format (04||x||y)
            if not pub_key.startswith('04'):
                # print("SM2加密出错:", "Public key must be in uncompressed format starting with 04.")
                raise ValueError("Public key must be in uncompressed format starting with 04.")

            # 2. Parse public key coordinates
            pb_x = int(pub_key[2:66], 16)
            pb_y = int(pub_key[66:], 16)
            Pb = (pb_x, pb_y)

            # 3. Convert plaintext string to bytes
            M = plaintext.encode('utf-8')

            # 4. Generate random number k in [1, n-1]
            k = secrets.randbelow(n - 1)
            while k <= 0:
                k = secrets.randbelow(n - 1)

            # 5. Calculate C1 = [k]G
            c1_point = _scalar_mult(k, (Gx, Gy), p, a)
            if not c1_point:
                # print("SM2加密出错:", "Error generating C1: Point at infinity")
                raise ValueError("Error generating C1: Point at infinity")

            # Serialize C1 in uncompressed format (04||x||y)。为了兼容，用bytes(bytearray.fromhex())替换了bytes.fromhex()
            c1 = bytes(bytearray.fromhex('04')) + c1_point[0].to_bytes(32, 'big') + c1_point[1].to_bytes(32, 'big')

            # 6. Calculate S = [k]Pb
            s_point = _scalar_mult(k, Pb, p, a)
            if not s_point:
                # print("SM2加密出错:", "Error generating S: Point at infinity")
                raise ValueError("Error generating S: Point at infinity")

            Sx, Sy = s_point

            # 7. Derive key K using KDF(Sx, Sy, klen=len(M))
            k_len = len(M)
            K = _kdf(Sx, Sy, k_len)

            # 8. Calculate C2 = M XOR K
            c2 = bytes([a ^ b for a, b in zip(M, K)])

            # 9. Calculate C3 = Hash(Sx || M || Sy)
            hash_hex = SM3.hash(Sx.to_bytes(32, 'big') + M + Sy.to_bytes(32, 'big'))
            c3 = bytes(bytearray.fromhex(hash_hex))  # 为了兼容，用bytes(bytearray.fromhex())替换了bytes.fromhex()

            # 10. Return C1 || C3 || C2
            cipherText = (c1 + c3 + c2).hex()
            # print("SM2加密结果:", str(cipherText))
            sys.stdout.flush()
            return cipherText  # 返回十六进制字符
        except Exception as err:
            # print("SM2加密出错:", str(err))
            return str(err)

    @classmethod
    def decrypt(cls, pri_key, ciphertext):
        """
        国密SM2解密
        :param pri_key:sm2解密私钥(十六进制字符)
        :param ciphertext: 已加密的十六进制字符
        :return: 原字符串
        """

        def _inverse_mod(a, n):
            if a == 0:
                return 0
            lm, hm = 1, 0
            low, high = a % n, n
            while low > 1:
                ratio = high // low
                nm, new = hm - lm * ratio, high - low * ratio
                lm, low, hm, high = nm, new, lm, low
            return lm % n

        def _point_add(P, Q, p, a):
            if not P: return Q
            if not Q: return P
            Px, Py = P
            Qx, Qy = Q
            if Px == Qx and Py != Qy: return None
            if P == Q:
                lam = (3 * Px * Px + a) * _inverse_mod(2 * Py, p) % p
            else:
                lam = (Qy - Py) * _inverse_mod(Qx - Px, p) % p
            x = (lam * lam - Px - Qx) % p
            y = (lam * (Px - x) - Py) % p
            return (x, y)

        def _scalar_mult(k, P, p, a):
            R = None
            N = P
            while k:
                if k & 1:
                    R = _point_add(R, N, p, a)
                N = _point_add(N, N, p, a)
                k >>= 1
            return R

        def _kdf(x, y, klen):
            ct = 1
            K = b''
            while len(K) < klen:
                hash_hex = SM3.hash(x.to_bytes(32, 'big') + y.to_bytes(32, 'big') + struct.pack('>I', ct))
                K += bytes.fromhex(hash_hex)
                ct += 1
            return K[:klen]

        # print("SM2解密入参:", pri_key, ciphertext)
        try:
            # 1. 定义曲线参数 (必须与加密时一致)
            p = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16)
            a = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16)
            n = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16)

            # 2. 解析密文 (C1 || C3 || C2)
            # C1 长度: 1字节(04) + 32字节(X) + 32字节(Y) = 65字节 -> 130个十六进制字符
            # C3 长度: SM3输出 32字节 -> 64个十六进制字符
            c1_len_hex = 130
            c3_len_hex = 64

            if len(ciphertext) < c1_len_hex + c3_len_hex:
                # print("SM2解密出错:", "密文长度过短，格式错误")
                raise ValueError("密文长度过短，格式错误")

            c1_hex = ciphertext[0:c1_len_hex]
            c3_hex = ciphertext[c1_len_hex:c1_len_hex + c3_len_hex]
            c2_hex = ciphertext[c1_len_hex + c3_len_hex:]

            # 3. 解析 C1 (椭圆曲线点)
            if not c1_hex.startswith('04'):
                # print("SM2解密出错:", "C1 格式错误，非压缩格式")
                raise ValueError("C1 格式错误，非压缩格式")
            c1_x = int(c1_hex[2:66], 16)
            c1_y = int(c1_hex[66:], 16)
            C1 = (c1_x, c1_y)

            # 4. 解析私钥
            d = int(pri_key, 16)

            # 5. 计算共享秘密点 S = [d]C1
            # 理论上 S = [d][k]G = [k][d]G = [k]Pb
            S_point = _scalar_mult(d, C1, p, a)
            if not S_point:
                # print("SM2解密出错:", "计算共享秘密点失败：无穷远点")
                raise ValueError("计算共享秘密点失败：无穷远点")

            Sx, Sy = S_point

            # 6. 准备解密 C2
            c2_bytes = bytes.fromhex(c2_hex)
            k_len = len(c2_bytes)

            # 7. 完整性校验 (计算 C3' 并与接收到的 C3 比对)
            # 标准流程：先解密或先校验均可，这里先计算哈希校验
            # Hash(Sx || M || Sy)
            # 注意：这里我们暂时还不知道明文 M，但校验逻辑要求必须包含 M。
            # 因此我们需要先通过异或还原出 M，然后再校验；
            # 或者先假设校验通过，解密后再校验。
            # 为了严谨，我们先解密，再校验。

            # 8. 生成密钥流并解密 C2 -> M
            K = _kdf(Sx, Sy, k_len)
            m_bytes = bytes([a ^ b for a, b in zip(c2_bytes, K)])

            # 9. 验证 C3
            # 计算 Hash(Sx || M || Sy)
            hash_hex = SM3.hash(Sx.to_bytes(32, 'big') + m_bytes + Sy.to_bytes(32, 'big'))
            calculated_c3 = bytes.fromhex(hash_hex)
            received_c3 = bytes.fromhex(c3_hex)

            if calculated_c3 != received_c3:
                # print("SM2解密出错:", "密文完整性校验失败 (C3不匹配)，可能密钥错误或数据被篡改。")
                raise ValueError("密文完整性校验失败 (C3不匹配)，可能密钥错误或数据被篡改。")

            # 10. 返回明文
            plainText = m_bytes.decode('utf-8')
            # print("SM2解密结果:", plainText)
            sys.stdout.flush()
            return plainText
        except Exception as err:
            # print("SM2解密出错:", str(err))
            return str(err)

    @classmethod
    def encryptToBase64(cls, pub_key_hex, plain_text):
        """
        国密SM2加密，返回Base64结果
        :param pub_key_hex: sm2加密公钥(十六进制字符)
        :param plain_text: 原始数据
        :return: 加密结果Base64字符串
        """
        # ================= SM2 基础参数 =================
        # 椭圆曲线参数 y^2 = x^3 + ax + b (mod p)
        SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
        SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
        SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
        SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
        SM2_GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
        SM2_GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
        # 生成点 G
        G = (SM2_GX, SM2_GY)

        # ================= 基础数学运算 =================
        def _mod_inverse(a, m):
            """扩展欧几里得算法求模逆"""

            def _extended_gcd(a, b):
                if a == 0:
                    return b, 0, 1
                gcd, x1, y1 = _extended_gcd(b % a, a)
                x = y1 - (b // a) * x1
                y = x1
                return gcd, x, y

            if a < 0:
                a = a % m
            g, x, _ = _extended_gcd(a, m)
            if g != 1:
                return None
            return x % m

        def _point_add(p1, p2):
            """椭圆曲线点加"""
            if p1 is None: return p2
            if p2 is None: return p1

            x1, y1 = p1
            x2, y2 = p2

            if x1 == x2 and y1 != y2:
                return None  # 无穷远点

            if x1 == x2:
                # 倍点
                # s = (3 * x1^2 + a) / (2 * y1)
                num = (3 * x1 * x1 + SM2_A) % SM2_P
                den = (2 * y1) % SM2_P
            else:
                # 点加
                # s = (y2 - y1) / (x2 - x1)
                num = (y2 - y1) % SM2_P
                den = (x2 - x1) % SM2_P

            inv_den = _mod_inverse(den, SM2_P)
            if inv_den is None: return None

            s = (num * inv_den) % SM2_P
            x3 = (s * s - x1 - x2) % SM2_P
            y3 = (s * (x1 - x3) - y1) % SM2_P
            return (x3, y3)

        def _point_multiply(k, point):
            """标量乘法：k * P"""
            result = None
            addend = point

            while k:
                if k & 1:
                    result = _point_add(result, addend)
                addend = _point_add(addend, addend)
                k >>= 1
            return result

        # ================= SM3 哈希算法 (简化实现) =================
        try:
            def sm3_hash(data):
                """计算SM3哈希值"""
                hash_hex = SM3.hash(data)
                return bytes.fromhex(hash_hex)

            def kdf(z, klen):
                """密钥派生函数"""
                ct = 0x00000001
                rc = b""

                # z是字节串
                while len(rc) < klen:
                    # z || ct
                    hash_input = z + ct.to_bytes(4, 'big')
                    h = sm3_hash(hash_input)
                    rc += h
                    ct += 1

                if klen % 32 != 0:
                    # 截断
                    rc = rc[:klen]
                return rc

            # ================= SM2 加密逻辑 =================
            def bytes_to_int(b):
                return int.from_bytes(b, 'big')

            def int_to_bytes(n, length):
                return n.to_bytes(length, 'big')

            # 1. 解析公钥
            pub_bytes = binascii.unhexlify(pub_key_hex)
            if len(pub_bytes) != 65 or pub_bytes[0] != 0x04:
                # print("SM2加密(Base64)出错:", "仅支持非压缩格式的公钥 (04开头)")
                raise ValueError("仅支持非压缩格式的公钥 (04开头)")

            px = bytes_to_int(pub_bytes[1:33])
            py = bytes_to_int(pub_bytes[33:65])
            P2 = (px, py)

            # 2. 生成随机数 k (1 <= k <= n-1)
            # 使用系统随机源
            k = random.SystemRandom().randint(1, SM2_N - 1)

            # 3. 计算 C1 = k * G
            C1_point = _point_multiply(k, G)
            # 序列化 C1 (非压缩 04 || x || y)
            c1_x = int_to_bytes(C1_point[0], 32)
            c1_y = int_to_bytes(C1_point[1], 32)
            C1 = b'\x04' + c1_x + c1_y

            # 4. 计算 S = k * P2 (x2, y2)
            S_point = _point_multiply(k, P2)
            s_x = int_to_bytes(S_point[0], 32)
            s_y = int_to_bytes(S_point[1], 32)

            # 5. 计算 t = KDF(x2 || y2, klen)
            plain_bytes = plain_text.encode('utf-8')
            t = kdf(s_x + s_y, len(plain_bytes))

            # 6. 计算 C2 = M ^ t
            C2 = bytearray()
            for i in range(len(plain_bytes)):
                C2.append(plain_bytes[i] ^ t[i])
            C2 = bytes(C2)

            # 7. 计算 C3 = Hash(x2 || M || y2)
            # 注意：国密标准是 x2 || M || y2
            c3_input = s_x + plain_bytes + s_y
            C3 = sm3_hash(c3_input)

            # 8. 拼接 C1 || C3 || C2
            cipher_bytes = C1 + C3 + C2

            # 9. Base64 编码
            cipher_result = base64.b64encode(cipher_bytes).decode('utf-8')
            # print("SM2加密(Base64)结果:", str(cipher_result))
            sys.stdout.flush()
            return cipher_result
        except Exception as err:
            # print("SM2加密(Base64)出错:", str(err))
            return str(err)

    @classmethod
    def decryptFromBase64(cls, pri_key_hex, cipher_text):
        """
        国密SM2解密
        :param pri_key_hex: sm2加密私钥(十六进制字符)
        :param cipher_text: 加密Base64字符串
        :return: 原文
        """
        # ================= SM2 基础参数 =================
        # 椭圆曲线参数 y^2 = x^3 + ax + b (mod p)
        SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
        SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
        SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
        SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
        SM2_GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
        SM2_GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
        # 生成点 G
        G = (SM2_GX, SM2_GY)

        # ================= 基础数学运算 =================
        def _mod_inverse(a, m):
            """扩展欧几里得算法求模逆"""

            def _extended_gcd(a, b):
                if a == 0:
                    return b, 0, 1
                gcd, x1, y1 = _extended_gcd(b % a, a)
                x = y1 - (b // a) * x1
                y = x1
                return gcd, x, y

            if a < 0:
                a = a % m
            g, x, _ = _extended_gcd(a, m)
            if g != 1:
                return None
            return x % m

        def _point_add(p1, p2):
            """椭圆曲线点加"""
            if p1 is None: return p2
            if p2 is None: return p1

            x1, y1 = p1
            x2, y2 = p2

            if x1 == x2 and y1 != y2:
                return None  # 无穷远点

            if x1 == x2:
                # 倍点
                # s = (3 * x1^2 + a) / (2 * y1)
                num = (3 * x1 * x1 + SM2_A) % SM2_P
                den = (2 * y1) % SM2_P
            else:
                # 点加
                # s = (y2 - y1) / (x2 - x1)
                num = (y2 - y1) % SM2_P
                den = (x2 - x1) % SM2_P

            inv_den = _mod_inverse(den, SM2_P)
            if inv_den is None: return None

            s = (num * inv_den) % SM2_P
            x3 = (s * s - x1 - x2) % SM2_P
            y3 = (s * (x1 - x3) - y1) % SM2_P
            return (x3, y3)

        def _point_multiply(k, point):
            """标量乘法：k * P"""
            result = None
            addend = point

            while k:
                if k & 1:
                    result = _point_add(result, addend)
                addend = _point_add(addend, addend)
                k >>= 1
            return result

        # ================= SM3 哈希算法 (简化实现) =================
        try:
            def sm3_hash(data):
                """计算SM3哈希值"""
                hash_hex = SM3.hash(data)
                return bytes.fromhex(hash_hex)

            def kdf(z, klen):
                """密钥派生函数"""
                ct = 0x00000001
                rc = b""

                # z是字节串
                while len(rc) < klen:
                    # z || ct
                    hash_input = z + ct.to_bytes(4, 'big')
                    h = sm3_hash(hash_input)
                    rc += h
                    ct += 1

                if klen % 32 != 0:
                    # 截断
                    rc = rc[:klen]
                return rc

            # ================= SM2 解密逻辑 =================
            def bytes_to_int(b):
                return int.from_bytes(b, 'big')

            def int_to_bytes(n, length):
                return n.to_bytes(length, 'big')

            # 1. Base64 解码
            cipher_bytes = base64.b64decode(cipher_text)

            # 2. 分离 C1, C3, C2
            # C1 (非压缩格式) 占 65 字节 (0x04 + 32x + 32y)
            # C3 (SM3哈希) 占 32 字节
            # C2 剩余部分
            c1_bytes = cipher_bytes[:65]
            c3_received = cipher_bytes[65:97]  # 65 + 32
            c2_bytes = cipher_bytes[97:]

            # 3. 解析 C1
            if c1_bytes[0] != 0x04:
                # print("SM2解密(Base64)出错:", "无效的C1格式")
                raise ValueError("无效的C1格式")
            c1_x = bytes_to_int(c1_bytes[1:33])
            c1_y = bytes_to_int(c1_bytes[33:65])
            C1_point = (c1_x, c1_y)

            # 4. 将十六进制私钥转换为整数
            d = int(pri_key_hex, 16)

            # 5. 计算 [d]C1
            # S = [d]C1 = [d]([k]G) = [dk]G = [k]([d]G) = [k]Ppub
            S_point = _point_multiply(d, C1_point)

            # 6. 检查 S 是否为无穷远点 (异常情况)
            if S_point is None:
                # print("SM2解密(Base64)出错:", "计算结果 S 为无穷远点，解密失败。")
                raise ValueError("计算结果 S 为无穷远点，解密失败。")

            s_x_bytes = int_to_bytes(S_point[0], 32)
            s_y_bytes = int_to_bytes(S_point[1], 32)

            # 7. 计算 t = KDF(x2 || y2, klen), 其中 klen 是 C2 的长度
            klen = len(c2_bytes)
            t = kdf(s_x_bytes + s_y_bytes, klen)

            # 8. 计算 M = C2 ^ t
            plain_bytes = bytearray()
            for i in range(len(c2_bytes)):
                plain_bytes.append(c2_bytes[i] ^ t[i])
            plain_text = bytes(plain_bytes).decode('utf-8')

            # 9. 验证 C3 (数据完整性校验)
            # 重新计算 C3' = Hash(x2 || M || y2)
            c3_calculated = sm3_hash(s_x_bytes + plain_bytes + s_y_bytes)

            if c3_calculated != c3_received:
                # print("SM2解密(Base64)出错:", "C3校验失败，数据可能被篡改或解密密钥错误。")
                raise ValueError("C3校验失败，数据可能被篡改或解密密钥错误。")

            # print("SM2解密(Base64)结果:", str(plain_text))
            sys.stdout.flush()
            return plain_text
        except Exception as err:
            # print("SM2解密(Base64)出错:", str(err))
            return str(err)

    @classmethod
    def sign(cls, pri_key, pub_key, value):
        """
        国密SM2签名（签名结果是DER格式）
        :param pri_key: sm2签名私钥(十六进制字符)
        :param pub_key: sm2签名公钥(十六进制字符)
        :param value: 待签名的字符串
        :return: sm2签名后的十六进制字符（DER格式）
        """
        try:
            # SM2椭圆曲线标准参数
            p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
            a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
            b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
            n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
            Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
            Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

            def mod_inverse(a, m):
                """计算模逆"""

                def extended_gcd(a, b):
                    if a == 0: return b, 0, 1
                    gcd, x1, y1 = extended_gcd(b % a, a)
                    return gcd, y1 - (b // a) * x1, x1

                gcd, x, _ = extended_gcd(a % m, m)
                if gcd != 1: raise ValueError("Modular inverse does not exist")
                return (x % m + m) % m

            def point_add(P, Q):
                """椭圆曲线上点加法"""
                if P is None: return Q
                if Q is None: return P
                x1, y1 = P
                x2, y2 = Q
                if x1 == x2 and y1 == y2:
                    if y1 == 0: return None
                    lam = ((3 * x1 * x1 + a) * mod_inverse(2 * y1, p)) % p
                else:
                    if x1 == x2: return None
                    lam = ((y2 - y1) * mod_inverse(x2 - x1, p)) % p
                x3 = (lam * lam - x1 - x2) % p
                y3 = (lam * (x1 - x3) - y1) % p
                return (x3, y3)

            def scalar_mult(k, P):
                """标量乘法"""
                result = None
                addend = P
                while k:
                    if k & 1: result = point_add(result, addend)
                    addend = point_add(addend, addend)
                    k >>= 1
                return result

            # 解析输入参数
            d = int(pri_key, 16)
            Px = int(pub_key[2:66], 16)
            Py = int(pub_key[66:], 16)

            # 计算ZA = SM3(ENTLA || IDA || a || b || Gx || Gy || Px || Py)
            ENTLA = 0x0080  # 用户ID长度(比特)，通常为128
            IDA = b'1234567812345678'  # 默认用户ID

            za_input = ENTLA.to_bytes(2, 'big') + IDA
            za_input += a.to_bytes(32, 'big')
            za_input += b.to_bytes(32, 'big')
            za_input += Gx.to_bytes(32, 'big')
            za_input += Gy.to_bytes(32, 'big')
            za_input += Px.to_bytes(32, 'big')
            za_input += Py.to_bytes(32, 'big')

            Za = bytes.fromhex(SM3.hash(za_input))

            # 计算e = SM3(Za || M)
            e_msg = Za + value.encode('utf-8')
            e_hex = SM3.hash(e_msg)
            e = int(e_hex, 16) % n

            # SM2签名算法
            success = False
            attempt = 0
            r, s = 0, 0

            while not success and attempt < 1000:
                k = random.randint(1, n - 1)
                point_result = scalar_mult(k, (Gx, Gy))
                if point_result is None:
                    attempt += 1
                    continue
                x1, y1 = point_result

                r = (e + x1) % n
                if r == 0 or (r + k) % n == 0:
                    attempt += 1
                    continue

                d_plus_1 = (1 + d) % n
                d_plus_1_inv = mod_inverse(d_plus_1, n)
                s = (d_plus_1_inv * (k - r * d)) % n

                if s == 0:
                    attempt += 1
                    continue
                success = True

            if not success:
                raise Exception("无法生成有效的签名")

            # 编码为DER格式
            def encode_der_integer(val):
                byte_val = val.to_bytes(32, 'big')
                while len(byte_val) > 1 and byte_val[0] == 0 and not (byte_val[1] & 0x80):
                    byte_val = byte_val[1:]
                if byte_val and (byte_val[0] & 0x80):
                    byte_val = b'\x00' + byte_val
                return byte_val

            r_bytes = encode_der_integer(r)
            s_bytes = encode_der_integer(s)

            r_len = len(r_bytes)
            s_len = len(s_bytes)
            seq_len = 2 + r_len + 2 + s_len

            der_sig = bytearray()
            der_sig.append(0x30)
            der_sig.append(seq_len)
            der_sig.append(0x02)
            der_sig.append(r_len)
            der_sig.extend(r_bytes)
            der_sig.append(0x02)
            der_sig.append(s_len)
            der_sig.extend(s_bytes)
            return der_sig.hex()
        except Exception as err:
            # print(f"SM2签名出错: {err}")
            return str(err)

    @classmethod
    def verify(cls, pub_key, sign, value):
        """
        国密SM2验签（签名结果是DER格式，非标准格式）
        :param pub_key: sm2验签公钥(十六进制字符)
        :param sign: 已签名的十六进制字符（DER格式）
        :param value: 原始数据
        :return: 验签结果（1通过，0不通过）
        """
        try:
            # SM2椭圆曲线标准参数
            p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
            a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
            b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
            n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
            Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
            Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

            def mod_inverse(a, m):
                """计算模逆"""

                def extended_gcd(a, b):
                    if a == 0: return b, 0, 1
                    gcd, x1, y1 = extended_gcd(b % a, a)
                    return gcd, y1 - (b // a) * x1, x1

                gcd, x, _ = extended_gcd(a % m, m)
                if gcd != 1: raise ValueError("Modular inverse does not exist")
                return (x % m + m) % m

            def point_add(P, Q):
                """椭圆曲线上点加法"""
                if P is None: return Q
                if Q is None: return P
                x1, y1 = P
                x2, y2 = Q
                if x1 == x2 and y1 == y2:
                    if y1 == 0: return None
                    lam = ((3 * x1 * x1 + a) * mod_inverse(2 * y1, p)) % p
                else:
                    if x1 == x2: return None
                    lam = ((y2 - y1) * mod_inverse(x2 - x1, p)) % p
                x3 = (lam * lam - x1 - x2) % p
                y3 = (lam * (x1 - x3) - y1) % p
                return (x3, y3)

            def scalar_mult(k, P):
                """标量乘法"""
                result = None
                addend = P
                while k:
                    if k & 1: result = point_add(result, addend)
                    addend = point_add(addend, addend)
                    k >>= 1
                return result

            # 解析公钥
            Px = int(pub_key[2:66], 16)
            Py = int(pub_key[66:], 16)
            PA = (Px, Py)

            # 解析DER格式签名
            try:
                sig_bytes = bytes.fromhex(sign)
            except ValueError:
                return "0"

            # 验证DER格式合法性
            if len(sig_bytes) < 8 or sig_bytes[0] != 0x30:  # SEQUENCE tag
                return "0"

            seq_len = sig_bytes[1]
            if len(sig_bytes) != seq_len + 2:
                return "0"

            # 解析 r
            if len(sig_bytes) < 4: return "0"
            r_tag = sig_bytes[2]
            if r_tag != 0x02: return "0"  # INTEGER tag
            r_len = sig_bytes[3]
            if len(sig_bytes) < 4 + r_len: return "0"
            r_start = 4
            r_end = r_start + r_len
            r_bytes = sig_bytes[r_start:r_end]
            r = int.from_bytes(r_bytes, 'big')

            # 解析 s
            if len(sig_bytes) <= r_end + 1: return "0"
            s_tag = sig_bytes[r_end]
            if s_tag != 0x02: return "0"  # INTEGER tag
            s_len = sig_bytes[r_end + 1]
            if len(sig_bytes) < r_end + 2 + s_len: return "0"
            s_start = r_end + 2
            s_end = s_start + s_len
            s_bytes = sig_bytes[s_start:s_end]
            s = int.from_bytes(s_bytes, 'big')

            # 验证r和s的范围
            if r <= 0 or r >= n or s <= 0 or s >= n:
                return "0"

            # 计算ZA = SM3(ENTLA || IDA || a || b || Gx || Gy || Px || Py)
            ENTLA = 0x0080  # 用户ID长度(比特)，通常为128
            IDA = b'1234567812345678'  # 默认用户ID

            za_input = ENTLA.to_bytes(2, 'big') + IDA
            za_input += a.to_bytes(32, 'big')
            za_input += b.to_bytes(32, 'big')
            za_input += Gx.to_bytes(32, 'big')
            za_input += Gy.to_bytes(32, 'big')
            za_input += Px.to_bytes(32, 'big')
            za_input += Py.to_bytes(32, 'big')

            Za = bytes.fromhex(SM3.hash(za_input))

            # 计算e = SM3(Za || M)
            e_msg = Za + value.encode('utf-8')
            e_hex = SM3.hash(e_msg)
            e = int(e_hex, 16) % n

            # 验签核心过程
            t = (r + s) % n
            if t == 0:
                return "0"

            # 计算点 (x1, y1) = s*G + t*PA
            sG = scalar_mult(s, (Gx, Gy))
            tPA = scalar_mult(t, PA)
            point_result = point_add(sG, tPA)

            if point_result is None:
                return "0"
            x1, y1 = point_result

            # 验证 r' = (e + x1) mod n 是否等于 r
            rp = (e + x1) % n
            verifyResult = "1" if rp == r else "0"
            return verifyResult
        except Exception as err:
            # print(f"SM2验签出错: {err}")
            return str(err)
