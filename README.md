# CE100, Homework 4

## AI2X Team 

Members;

- Suleyman Mert ALMALI, (suleymanmert_almali21@erdogan.edu.tr), [@Mertalmali4](https://github.com/Mertalmali4) 

- Eray Burak CAKIR, (erayburak_cakir21@erdogan.edu.tr), [@cakirerayburak](https://github.com/cakirerayburak)

Instructor: 
- Ugur CORUH, [@ucoruh](https://github.com/ucoruh)

## Test Coverage

[![.NET Core Release with Test Coverage Control](https://github.com/cakirerayburak/ce100-hw4-eray-burak-cakir/actions/workflows/build_check_ubuntu_windows.yml/badge.svg)](https://github.com/cakirerayburak/ce100-hw4-eray-burak-cakir/actions/workflows/build_check_ubuntu_windows.yml)

**Coverage**

- ![All](assets/badge_combined.svg)

**Branch Coverage**

- ![Branch Coverage](assets/badge_branchcoverage.svg)

**Line Coverage**

- ![Line Coverage](assets/badge_linecoverage.svg)

**Method Coverage**

- ![Method Coverage](assets/badge_methodcoverage.svg)



# AES Encryption and HOTP Key Generation

This project demonstrates the implementation of AES encryption, binary conversion, and HOTP key generation algorithms using C#. It provides a secure method to convert text files into binary representation, encrypt the binary data using AES, decrypt the encrypted data, and generate a one-time key using the HOTP algorithm.

## Features

- Text-to-binary conversion
- AES encryption and decryption
- HOTP key generation

## Prerequisites

- .NET Core 6..0 Framework 

## Usage

1. Clone the repository:
- git clone https://github.com/cakirerayburak/ce100-hw4-eray-burak-cakir.git
2. Build the project to compile the code.
3. The names and extensions of the files to be converted to binary, encrypted, and decrypted :
- Source text file: astyle-options.txt
- Binary file: Secret.bin
- Encrypted file: Encrypted.enc
- Decrypted file: Decrypted.txt
```csharp
 string sourceFile = "astyle-options.txt"; 
 string binaryFile = "Secret.bin"; 
 string encryptedFile = "Encrypted.enc";
 string decryptedFile = "Decrypted.txt"; 
```

4. Convert a text file to binary:
```csharp
 ConvertToBinary(sourceFile, binaryFile);
 Console.WriteLine("The Text File is Converted to a Binary File."); 
```
5. Encrypt the binary data using AES:
```csharp
 TransformFile(binaryFile, encryptedFile, 1);
 Console.WriteLine("Encrypting the File: " + encryptedFile);
```
6. Decrypt the encrypted data:
```csharp
 TransformFile(encryptedFile, decryptedFile, 0);
 Console.WriteLine("Decrypting the File: " + decryptedFile);
```
7. Generate a one-time key using HOTP:
```csharp
 byte[] key = Encoding.ASCII.GetBytes("my_secret_key"); 
 long counter = 12345; 
 string oneTimePassword = HOTP.GenerateHotp(key, counter);
 Console.WriteLine("One-Time Password: " + oneTimePassword);
```

## Testing
- The project includes unit tests to validate the functionality of AES encryption, decryption, binary conversion, and HOTP key generation. 
- You can run the tests using your preferred testing framework or the built-in testing tools of your development environment.
