using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    /// <summary>
    /// 增强认证证书扩展方法类。
    /// </summary>
    public static class EnhancedAuthenticationCertificateExtensions
    {
        /// <summary>
        /// 导出公钥。
        /// </summary>
        /// <param name="rsa">RSA加密类。</param>
        /// <returns>返回公钥数据。</returns>
        public static byte[] ExportPublicKey(this RSA rsa)
        {
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            var parameters = rsa.ExportParameters(false);
            var data = parameters.Exponent.Concat(parameters.Modulus).ToArray();
            return data;
        }

        /// <summary>
        /// 导出私钥。
        /// </summary>
        /// <param name="rsa">RSA加密类。</param>
        /// <returns>返回私钥数据。</returns>
        public static byte[] ExportPrivateKey(this RSA rsa)
        {
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            var parameters = rsa.ExportParameters(true);
            var data = parameters.D
                .Concat(parameters.DP)
                .Concat(parameters.DQ)
                .Concat(parameters.Exponent)
                .Concat(parameters.InverseQ)
                .Concat(parameters.Modulus)
                .Concat(parameters.P)
                .Concat(parameters.Q)
                .ToArray();
            return data;
        }

        /// <summary>
        /// 导入公钥。
        /// </summary>
        /// <param name="rsa">RSA加密类。</param>
        /// <param name="keySize">密钥大小。</param>
        /// <param name="data">密钥数据。</param>
        /// <param name="startIndex">开始位置。</param>
        public static void ImportPublicKey(this RSA rsa, int keySize, byte[] data, int startIndex)
        {
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            if (keySize < 1024)
                throw new ArgumentOutOfRangeException(nameof(keySize), "密钥长度不能小于1024。");
            if (keySize % 1024 != 0)
                throw new ArgumentException(nameof(keySize), "密钥长度必须是1024的倍数。");
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (startIndex < 0)
                throw new ArgumentOutOfRangeException(nameof(startIndex), "开始位置不能小于0。");
            if (startIndex + 3 + keySize / 8 >= data.Length)
                throw new ArgumentException(nameof(data), "数据丢失。");
            RSAParameters parameters = new RSAParameters();
            parameters.Exponent = data.Skip(startIndex).Take(3).ToArray();
            parameters.Modulus = data.Skip(startIndex + 3).Take(keySize / 8).ToArray();
            rsa.ImportParameters(parameters);
        }

        /// <summary>
        /// 导入私钥。
        /// </summary>
        /// <param name="rsa">RSA加密类。</param>
        /// <param name="keySize">密钥大小。</param>
        /// <param name="data">密钥数据。</param>
        /// <param name="startIndex">开始位置。</param>
        public static void ImportPrivateKey(this RSA rsa, int keySize, byte[] data, int startIndex)
        {
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            if (keySize < 1024)
                throw new ArgumentOutOfRangeException(nameof(keySize), "密钥长度不能小于1024。");
            if (keySize % 1024 != 0)
                throw new ArgumentException(nameof(keySize), "密钥长度必须是1024的倍数。");
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (startIndex < 0)
                throw new ArgumentOutOfRangeException(nameof(startIndex), "开始位置不能小于0。");
            if (startIndex + 3 + keySize / 8 >= data.Length)
                throw new ArgumentException(nameof(data), "数据丢失。");
            var max = keySize / 8;
            var min = max / 2;
            RSAParameters parameters = new RSAParameters();
            parameters.D = data.Skip(startIndex).Take(max).ToArray();
            parameters.DP = data.Skip(startIndex + max).Take(min).ToArray();
            parameters.DQ = data.Skip(startIndex + max + min).Take(min).ToArray();
            parameters.Exponent = data.Skip(startIndex + max + min * 2).Take(3).ToArray();
            parameters.InverseQ = data.Skip(startIndex + max + min * 2 + 3).Take(min).ToArray();
            parameters.Modulus = data.Skip(startIndex + max + min * 3 + 3).Take(max).ToArray();
            parameters.P = data.Skip(startIndex + max * 2 + min * 3 + 3).Take(min).ToArray();
            parameters.Q = data.Skip(startIndex + max * 2 + min * 4 + 3).Take(min).ToArray();
            rsa.ImportParameters(parameters);
        }

        /// <summary>
        /// 签名数据。
        /// </summary>
        /// <param name="rsa">RSA加密类。</param>
        /// <param name="data">要签名的数据。</param>
        /// <param name="hashMode">哈希模式。</param>
        /// <returns>返回签名数据。</returns>
        public static byte[] SignData(this RSA rsa, byte[] data, EnhancedAuthenticationCertificateHashMode hashMode)
        {
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            if (data == null)
                throw new ArgumentNullException(nameof(data));
#if NETSTANDARD1_3 || NETSTANDARD2_0 ||NET46
            HashAlgorithmName hashName;
            switch (hashMode)
            {
                case EnhancedAuthenticationCertificateHashMode.MD5:
                    hashName = HashAlgorithmName.MD5;
                    break;
                case EnhancedAuthenticationCertificateHashMode.SHA1:
                    hashName = HashAlgorithmName.SHA1;
                    break;
                case EnhancedAuthenticationCertificateHashMode.SHA256:
                    hashName = HashAlgorithmName.SHA256;
                    break;
                case EnhancedAuthenticationCertificateHashMode.SHA384:
                    hashName = HashAlgorithmName.SHA384;
                    break;
                case EnhancedAuthenticationCertificateHashMode.SHA512:
                    hashName = HashAlgorithmName.SHA512;
                    break;
                default:
                    throw new CryptographicException("不支持的哈希算法。");
            }
            return rsa.SignData(data, hashName, RSASignaturePadding.Pkcs1);
#else
            RSAPKCS1SignatureFormatter formatter = new RSAPKCS1SignatureFormatter();
            formatter.SetHashAlgorithm(hashMode.ToString());
            return formatter.CreateSignature(data);
#endif
        }

        /// <summary>
        /// 验证签名。
        /// </summary>
        /// <param name="rsa">RSA加密类。</param>
        /// <param name="data">被签名的数据。</param>
        /// <param name="signature">签名数据。</param>
        /// <param name="hashMode">哈希模式。</param>
        /// <returns>返回是否验证成功。</returns>
        public static bool VerifyData(this RSA rsa, byte[] data, byte[] signature, EnhancedAuthenticationCertificateHashMode hashMode)
        {
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (data == null)
                throw new ArgumentNullException(nameof(data));
#if NETSTANDARD1_3 || NETSTANDARD2_0 ||NET46
            HashAlgorithmName hashName;
            switch (hashMode)
            {
                case EnhancedAuthenticationCertificateHashMode.MD5:
                    hashName = HashAlgorithmName.MD5;
                    break;
                case EnhancedAuthenticationCertificateHashMode.SHA1:
                    hashName = HashAlgorithmName.SHA1;
                    break;
                case EnhancedAuthenticationCertificateHashMode.SHA256:
                    hashName = HashAlgorithmName.SHA256;
                    break;
                case EnhancedAuthenticationCertificateHashMode.SHA384:
                    hashName = HashAlgorithmName.SHA384;
                    break;
                case EnhancedAuthenticationCertificateHashMode.SHA512:
                    hashName = HashAlgorithmName.SHA512;
                    break;
                default:
                    throw new CryptographicException("不支持的哈希算法。");
            }
            return rsa.VerifyData(data, signature, hashName, RSASignaturePadding.Pkcs1);
#else
            RSAPKCS1SignatureDeformatter formatter = new RSAPKCS1SignatureDeformatter();
            formatter.SetHashAlgorithm(hashMode.ToString());
            return formatter.VerifySignature(data, signature);
#endif
        }

        /// <summary>
        /// 加密数据。
        /// </summary>
        /// <param name="rsa">RSA加密类。</param>
        /// <param name="data">被加密的数据。</param>
        /// <returns></returns>
        public static byte[] Encrypt(this RSA rsa, byte[] data)
        {
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            if (data == null)
                throw new ArgumentNullException(nameof(data));
#if NET45 || NET40
            return rsa.EncryptValue(data);
#else
            return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
#endif
        }

        /// <summary>
        /// 解密数据。
        /// </summary>
        /// <param name="rsa">RSA加密类。</param>
        /// <param name="data">被解密的数据。</param>
        /// <returns></returns>
        public static byte[] Decrypt(this RSA rsa, byte[] data)
        {
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            if (data == null)
                throw new ArgumentNullException(nameof(data));
#if NET45 || NET40
            return rsa.DecryptValue(data);
#else
            return rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
#endif
        }
    }
}