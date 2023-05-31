using Algorithms;
using System.Text;
using System.Security.Cryptography;

/** @author Eray Burak CAKIR And Suleyman Mert ALMALI
 */

namespace ConsoleApp
{
    /// <summary>
    /// A console application to demonstrate file transformation and encryption.
    /// </summary>
    class Program : AES
    {
        static void Main()
        {
            /// <summary>
            /// This code demonstrates file conversion, encryption, and decryption operations.
            /// </summary>

            string sourceFile = "astyle-options.txt"; ///< The path and filename of the source text file.
            string binaryFile = "Secret.bin"; ///< The path and filename of the binary file.
            string encryptedFile = "Encrypted.enc"; ///< The path and filename of the encrypted file.
            string decryptedFile = "Decrypted.txt"; ///< The path and filename of the decrypted file.


            

            // Convert text file to binary
            ConvertToBinary(sourceFile, binaryFile);
            Console.WriteLine("The Text File is Converted to a Binary File.");

            // Encrypt and save the file
            TransformFile(binaryFile, encryptedFile, 1);
            Console.WriteLine("Encrypting the File: " + encryptedFile);

            // Decrypt the encrypted file
            TransformFile(encryptedFile, decryptedFile, 0);
            Console.WriteLine("Decrypting the File: " + decryptedFile);

            Console.WriteLine("\n*********************");

            string Key = "mysecret";
            DESHelper desHelper = new DESHelper(Key);

            string plainText = "Hello World!";
            string encryptedText = desHelper.Encrypt(plainText);
            string decryptedText = desHelper.Decrypt(encryptedText);

            Console.WriteLine("Plain Text: " + plainText);
            Console.WriteLine("Encrypted Text: " + encryptedText);
            Console.WriteLine("Decrypted Text: " + decryptedText);


            string filePath = "astyle-options.txt"; 
            byte[] fileData = File.ReadAllBytes(filePath);

            uint crc32 = CRC32.ComputeCRC32(fileData);

            Console.WriteLine("*********************");
            Console.WriteLine("CRC32: " + crc32.ToString("X8"));

            /// <summary>
            /// This code generates a one-time password using the HOTP algorithm.
            /// </summary>
            Console.WriteLine("*********************");
            byte[] data = Encoding.UTF8.GetBytes("Hello, World!");

            MD5Helper md5Helper = new MD5Helper();
            byte[] md5Hash = md5Helper.ComputeMD5(data);
            string md5Hex = md5Helper.ByteArrayToHex(md5Hash);

            Console.WriteLine("\nMD5: " + md5Hex);


            byte[] key = Encoding.ASCII.GetBytes("my_secret_key"); // Specify your secret key here
            long counter = 12345; // Specify the counter value here

            string oneTimePassword = HOTP.GenerateHotp(key, counter);
            Console.WriteLine("One-Time Password: " + oneTimePassword);

        }
    }
}










