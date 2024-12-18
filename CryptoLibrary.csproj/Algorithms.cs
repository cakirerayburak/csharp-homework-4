﻿using System;
using System.Collections;
using System.IO;
using System.Security.Cryptography;
using System.Text;

/** @author Eray Burak CAKIR And Suleyman Mert ALMALI
 */

namespace Algorithms
{

    /// <summary>
    /// Provides methods for file transformation and encryption.
    /// </summary>
    public class AES
    {
        private const int BytesBlockSize = 16;
        private static readonly byte[] Key = Encoding.UTF8.GetBytes("mysecretkey12345");


        /// <summary>
        /// Converts a file to binary format.
        /// </summary>
        /// <param name="sourceFile">The path of the source file.</param>
        /// <param name="destinationFile">The path of the destination file.</param>


        public static void ConvertToBinary(string sourceFile, string destinationFile)
        {
            File.Copy(sourceFile, destinationFile, true);
        }


        /// <summary>
        /// Transforms a file based on the specified operation.
        /// </summary>
        /// <param name="sourceFilePath">The path of the source file.</param>
        /// <param name="destFilePath">The path of the destination file.</param>
        /// <param name="operation">The operation to be performed (0 for decryption, 1 for encryption).</param>

        public static void TransformFile(string sourceFilePath, string destFilePath, int operation)
        {
            if (operation == 1)
            {
                byte[] fileData = File.ReadAllBytes(sourceFilePath);
                byte[] sha1Hash = CalSha1(fileData);
                byte[] sha256Hash = CalSha256(fileData);
                byte[] buffer = BufferSet(sha1Hash, fileData, sha256Hash);
                byte[] encBuffer = EncData(buffer);
                File.WriteAllBytes(destFilePath, encBuffer);
            }
            else if (operation == 0)
            {
                byte[] encBuffer = File.ReadAllBytes(sourceFilePath);
                byte[] decryptedData = DecData(encBuffer);
                int length = BitConverter.ToInt32(decryptedData, 0);
                byte[] sha1Hash = new byte[20];
                byte[] fileData = new byte[length];
                byte[] sha256Hash = new byte[32];

                Buffer.BlockCopy(decryptedData, 4, sha1Hash, 0, 20);
                Buffer.BlockCopy(decryptedData, 24, fileData, 0, length);
                Buffer.BlockCopy(decryptedData, 24 + length, sha256Hash, 0, 32);

                byte[] calculatedSha1Hash = CalSha1(fileData);
                byte[] calculatedSha256Hash = CalSha256(fileData);

                bool sha1Validation = CompHash(sha1Hash, calculatedSha1Hash);
                bool sha256Validation = CompHash(sha256Hash, calculatedSha256Hash);

                File.WriteAllBytes(destFilePath, fileData);
            }
        }

        /// <summary>
        /// Sets up the buffer with the specified data.
        /// </summary>
        /// <param name="sha1D">The SHA1 hash of the file data.</param>
        /// <param name="fileData">The file data.</param>
        /// <param name="sha256D">The SHA256 hash of the file data.</param>
        /// <returns>The buffer containing the specified data.</returns>

        private static byte[] BufferSet(byte[] sha1Hash, byte[] fileData, byte[] sha256Hash)
        {
            int bufferLength = 4 + sha1Hash.Length + fileData.Length + sha256Hash.Length + BytesBlockSize;

            byte[] buffer = new byte[bufferLength];
            Buffer.BlockCopy(BitConverter.GetBytes(fileData.Length), 0, buffer, 0, 4);
            Buffer.BlockCopy(fileData, 0, buffer, 4 + sha1Hash.Length, fileData.Length);
            Buffer.BlockCopy(sha256Hash, 0, buffer, 4 + sha1Hash.Length + fileData.Length, sha256Hash.Length);
            return buffer;
        }

        /// <summary>
        /// Encrypts the provided data using AES encryption algorithm.
        /// </summary>
        /// <param name="data">The data to be encrypted.</param>
        /// <returns>The encrypted data.</returns>

        private static byte[] EncData(byte[] data)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Key;
                aes.IV = new byte[BytesBlockSize];
                aes.Mode = CipherMode.CBC;

                using (MemoryStream memStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock();
                    }

                    return memStream.ToArray();
                }
            }
        }

        /// <summary>
        /// Decrypts the provided data using AES encryption algorithm.
        /// </summary>
        /// <param name="data">The data to be decrypted.</param>
        /// <returns>The decrypted data.</returns>

        private static byte[] DecData(byte[] data)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Key;
                aes.IV = new byte[BytesBlockSize];
                aes.Mode = CipherMode.CBC;

                using (MemoryStream memStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock();
                    }

                    return memStream.ToArray();
                }
            }
        }


        /// <summary>
        /// Calculates the SHA1 hash of the provided data.
        /// </summary>
        /// <param name="data">The data to be hashed.</param>
        /// <returns>The SHA1 hash value.</returns>

        public static byte[] CalSha1(byte[] data)
        {
            using (SHA1 sha1 = SHA1.Create())
            {
                return sha1.ComputeHash(data);
            }
        }

        /// <summary>
        /// Calculates the SHA256 hash of the provided data.
        /// </summary>
        /// <param name="data">The data to be hashed.</param>
        /// <returns>The SHA256 hash value.</returns>

        public static byte[] CalSha256(byte[] data)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(data);
            }
        }


        /// <summary>
        /// Compares two hash values for equality.
        /// </summary>
        /// <param name="hash1">The first hash value.</param>
        /// <param name="hash2">The second hash value.</param>
        /// <returns>True if the hash values are equal, otherwise false.</returns>

        private static bool CompHash(byte[] hash1, byte[] hash2)
        {
            return StructuralComparisons.StructuralEqualityComparer.Equals(hash1, hash2);
        }
    }

    public class HOTP
    {

        /// <summary>
        /// Generates a one-time password (OTP) using the HOTP algorithm.
        /// </summary>
        /// <param name="key">The secret key used for generating the OTP.</param>
        /// <param name="counter">The counter value used in the OTP generation.</param>
        /// <param name="digits">The number of digits in the generated OTP. Default is 6.</param>
        /// <returns>The generated one-time password.</returns>

        public static string GenerateHotp(byte[] key, long counter, int digits = 6)
        {
            using var hmac = new HMACSHA1(key);
            byte[] counterBytes = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counterBytes);
            }

            byte[] hash = hmac.ComputeHash(counterBytes);
            int offset = hash[hash.Length - 1] & 0x0F;

            int oneTimePassword = ((hash[offset] & 0x7F) << 24 |
                                   (hash[offset + 1] & 0xFF) << 16 |
                                   (hash[offset + 2] & 0xFF) << 8 |
                                   (hash[offset + 3] & 0xFF)) % GetPowerOfTen(digits);

            return oneTimePassword.ToString().PadLeft(digits, '0');
        }

        /// <summary>
        /// Calculates the power of ten for the given number of digits.
        /// </summary>
        /// <param name="digits">The number of digits.</param>
        /// <returns>The power of ten.</returns>

        private static int GetPowerOfTen(int digits)
        {
            int result = 1;
            for (int i = 0; i < digits; i++)
            {
                result *= 10;
            }
            return result;
        }
    }
}

