using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Speeltuin.Tests
{
    [TestClass]
    public class SecurityTests
    {
        [TestMethod]
        public void Sha256HashTest()
        {
            const string password = "supers3retPass!@";
            var bytes = Encoding.Unicode.GetBytes(password);
            var hash = SHA256.Create().ComputeHash(bytes);

            Assert.IsTrue(hash.Length > 20);
        }

        [TestMethod]
        public void AesEncryptionAndDecryptionTest()
        {
            //Encrypt data
            using (var aes = new AesManaged())
            {
                aes.IV = new byte[aes.BlockSize / 8];

                const string secret = "secret!!";
                var orignalBytes = Encoding.Unicode.GetBytes(secret);
                byte[] encryptdBytes;

                using (var ms = new MemoryStream())
                using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(orignalBytes, 0, orignalBytes.Length); //Writes the bytes to the cryptostream
                    cs.FlushFinalBlock();
                    encryptdBytes = ms.ToArray();
                }

                //Decrypt data
                string resultAfterEncryption;
                using (var ms = new MemoryStream())
                using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(encryptdBytes, 0, encryptdBytes.Length);
                    resultAfterEncryption = Encoding.Unicode.GetString(ms.ToArray());
                }

                Assert.AreEqual(secret, resultAfterEncryption);
            }
        }
    }
}
