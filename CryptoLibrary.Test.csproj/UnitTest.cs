using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Algorithms;

/** @author Eray Burak CAKIR And Suleyman Mert ALMALI
 */

namespace AlgorithmsTest
{
    /// <summary>
    /// Contains unit tests for the AES class.
    /// </summary>
    public class AESAlgorithmTest : AES
    {
        private const string SourceFile = "testfile.txt";
        private const string BinaryFile = "testfile.bin";
        private const string EncryptedFile = "testfile.bin.enc";
        private const string DecryptedFile = "decrypted.txt";

        /// <summary>
        /// Tests the ConvertToBinary method when the source file exists.
        /// </summary>
        [Fact]
        public void ConvertToBinary_SourceFileExists_DestinationFileCreated()
        {
            // Arrange
            File.WriteAllText(SourceFile, "This is a test file.");

            // Act
            ConvertToBinary(SourceFile, BinaryFile);

            // Assert
            Assert.True(File.Exists(BinaryFile));
        }

        /// <summary>
        /// Tests the TransformFile method for encryption operation.
        /// </summary>
        [Fact]
        public void TransformFile_EncryptionOperation_FileEncryptedAndExists()
        {
            // Arrange
            File.WriteAllText(SourceFile, "This is a test file.");
            ConvertToBinary(SourceFile, BinaryFile);

            // Act
            TransformFile(BinaryFile, EncryptedFile, 1);

            // Assert
            Assert.True(File.Exists(EncryptedFile));
        }

        /// <summary>
        /// Tests the TransformFile method for decryption operation.
        /// </summary>
        [Fact]
        public void TransformFile_DecryptionOperation_FileDecryptedAndExists()
        {
            // Arrange
            File.WriteAllText(SourceFile, "This is a test file.");
            ConvertToBinary(SourceFile, BinaryFile);
            TransformFile(BinaryFile, EncryptedFile, 1);

            // Act
            TransformFile(EncryptedFile, DecryptedFile, 0);

            // Assert
            Assert.True(File.Exists(DecryptedFile));
        }

        /// <summary>
        /// Tests the TransformFile method for decryption operation and verifies that the decrypted file content matches the source file.
        /// </summary>
        [Fact]
        public void TransformFile_DecryptionOperation_DecryptedFileContentMatchesSourceFile()
        {
            // Arrange
            File.WriteAllText(SourceFile, "This is a test file.");
            ConvertToBinary(SourceFile, BinaryFile);
            TransformFile(BinaryFile, EncryptedFile, 1);
            TransformFile(EncryptedFile, DecryptedFile, 0);

            // Act
            string decryptedContent = File.ReadAllText(DecryptedFile);

            // Assert
            Assert.Equal("This is a test file.", decryptedContent);
        }

        /// <summary>
        /// Tests the TransformFile method for decryption operation and verifies that the file is decrypted successfully by comparing the original file data with the decrypted file data.
        /// </summary>
        [Fact]
        public void TransformFile_DecryptionOperation_FileDecryptedSuccessfully()
        {
            // Arrange
            File.WriteAllText(SourceFile, "This is a test file.");
            ConvertToBinary(SourceFile, BinaryFile);
            TransformFile(BinaryFile, EncryptedFile, 1);
            TransformFile(EncryptedFile, DecryptedFile, 0);

            // Act
            byte[] originalFileData = File.ReadAllBytes(SourceFile);
            byte[] decryptedFileData = File.ReadAllBytes(DecryptedFile);

            // Assert
            Assert.Equal(originalFileData, decryptedFileData);
        }

        /// <summary>
        /// Tests the TransformFile method for decryption operation and verifies that the hash of the original file matches the hash of the decrypted file.
        /// </summary>

        [Fact]
        public void TransformFile_DecryptionOperation_OriginalFileHashMatchesDecryptedFileHash()
        {
            // Arrange
            File.WriteAllText(SourceFile, "This is a test file.");
            ConvertToBinary(SourceFile, BinaryFile);
            TransformFile(BinaryFile, EncryptedFile, 1);
            TransformFile(EncryptedFile, DecryptedFile, 0);
            byte[] originalFileData = File.ReadAllBytes(SourceFile);
            byte[] decryptedFileData = File.ReadAllBytes(DecryptedFile);
            byte[] originalFileHash = CalSha256(originalFileData);
            byte[] decryptedFileHash = CalSha256(decryptedFileData);

            // Assert
            Assert.Equal(originalFileHash, decryptedFileHash);
        }

        /// <summary>
        /// Tests the TransformFile method for decryption operation and verifies that the hash of the original file does not match the hash of a modified file.
        /// </summary>
        [Fact]
        public void TransformFile_DecryptionOperation_OriginalFileHashDoesNotMatchModifiedFileHash()
        {
            // Arrange
            File.WriteAllText(SourceFile, "This is a test file.");
            ConvertToBinary(SourceFile, BinaryFile);
            TransformFile(BinaryFile, EncryptedFile, 1);
            File.WriteAllText(DecryptedFile, "Modified content");

            // Act
            byte[] originalFileData = File.ReadAllBytes(SourceFile);
            byte[] modifiedFileData = File.ReadAllBytes(DecryptedFile);
            byte[] originalFileHash = CalSha256(originalFileData);
            byte[] modifiedFileHash = CalSha256(modifiedFileData);

            // Assert
            Assert.NotEqual(originalFileHash, modifiedFileHash);
        }
    }


    public class DESHelperTests
    {
        private DESHelper desHelper;

        public DESHelperTests()
        {
            string key = "mysecret";
            desHelper = new DESHelper(key);
        }

        /// <summary>
        /// Test that encrypting and decrypting a plain text returns the original plain text.
        /// </summary>

        [Fact]
        public void Encrypt_Decrypt_ReturnsOriginalPlainText()
        {

            /// <summary>
            /// Test that encrypting different plain texts produces different encrypted outputs.
            /// </summary>

            // Arrange
            string key = "mysecret";
            string plainText = "Hello, World!";

            // Act
            DESHelper desHelper = new DESHelper(key);
            string encryptedText = desHelper.Encrypt(plainText);
            string decryptedText = desHelper.Decrypt(encryptedText);

            // Assert
            Assert.Equal(plainText, decryptedText);
        }

        [Fact]
        public void Encrypt_ReturnsDifferentOutputForDifferentPlainText()
        {
            // Arrange
            string key = "mysecret";
            string plainText1 = "Hello";
            string plainText2 = "World";

            // Act
            DESHelper desHelper = new DESHelper(key);
            string encryptedText1 = desHelper.Encrypt(plainText1);
            string encryptedText2 = desHelper.Encrypt(plainText2);

            // Assert
            Assert.NotEqual(encryptedText1, encryptedText2);
        }

        [Fact]
        public void Decrypt_ReturnsDifferentOutputForDifferentEncryptedText()
        {
            /// <summary>
            /// Test that decrypting different encrypted texts produces different decrypted outputs.
            /// </summary>

            // Arrange
            string key = "mysecret";
            DESHelper desHelper = new DESHelper(key);

            string plainText = "Hello World!";
            string encryptedText1 = desHelper.Encrypt(plainText);
            string encryptedText2 = desHelper.Encrypt(plainText + "123"); // Farklý þifrelenmiþ metin

            // Act
            string decryptedText1 = desHelper.Decrypt(encryptedText1);
            string decryptedText2 = desHelper.Decrypt(encryptedText2);

            // Assert
            Assert.Equal(plainText, decryptedText1);
            Assert.NotEqual(decryptedText1, decryptedText2);
        }
    }


    public class MD5HelperTests : MD5Helper
    {
        [Fact]
        public void ComputeMD5_ReturnsExpectedHash()
        {
            // Arrange
            byte[] data = Encoding.UTF8.GetBytes("Test data");
            string expectedHash = "ca1ea02c10b7c37f425b9b7dd86d5e11";

            // Act
           
            string actualHash = ByteArrayToHex(ComputeMD5(data));

            // Assert
            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void ByteArrayToHex_ReturnsExpectedHexString()
        {
            // Arrange
            byte[] data = new byte[] { 0xAB, 0xCD, 0xEF };
            string expectedHexString = "abcdef";

            // Act
            string actualHexString = ByteArrayToHex(data);

            // Assert
            Assert.Equal(expectedHexString, actualHexString);
        }
    }

    public class CRC32Tests : CRC32
    {
        /// <summary>
        /// Test that computing CRC32 hash for valid data returns the expected hash value.
        /// </summary>
        
        [Fact]
        public void ComputeCRC32_ValidData_ReturnsExpectedHash()
        {
            // Arrange
            byte[] data = new byte[] { 0x61, 0x62, 0x63 }; // Sample data: "abc"
            uint expectedHash = 0x352441C2; // Expected CRC32 hash value for "abc"

            // Act
            uint actualHash = ComputeCRC32(data);

            // Assert
            Assert.Equal(expectedHash, actualHash);
        }
    }


    public class HotpGeneratorTests : HOTP
    {
        [Fact]
        public void GenerateHotp_ReturnsCorrectOneTimePassword()
        {
            // Arrange
            byte[] key = Encoding.ASCII.GetBytes("my_secret_key");
            long counter = 624675;
            int digits = 6;
            string expectedOneTimePassword = "034371"; // Güncellenen beklenen sonuç

            // Act
            string actualOneTimePassword = GenerateHotp(key, counter, digits);

            // Assert
            Assert.Equal(expectedOneTimePassword, actualOneTimePassword);
        }
    }
}
