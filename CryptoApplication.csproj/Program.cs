using Algorithms;
using System.Text;


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


            /// <summary>
            /// This code generates a one-time password using the HOTP algorithm.
            /// </summary>


            byte[] key = Encoding.ASCII.GetBytes("my_secret_key"); // Specify your secret key here
            long counter = 12345; // Specify the counter value here

            string oneTimePassword = HOTP.GenerateHotp(key, counter);
            Console.WriteLine("One-Time Password: " + oneTimePassword);

        }
    }
}










