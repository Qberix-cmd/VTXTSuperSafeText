# VTXTSuperSafeText Library Usage Guide

## Overview
The **VTXTSuperSafeText** library provides functions for encrypting and decrypting text using AES-256-CBC with PBKDF2 key derivation.  
It is implemented as a native C++ DLL and can be used from multiple languages via FFI (Foreign Function Interface).

---

## Functions

### `int VTXTSuperSafeText_Encrypt(const unsigned char* input, int inputLen, const char* password, unsigned char* output, int maxLen)`
Encrypts raw data.

- **Parameters**
  - `input`: Pointer to the input data (plain text or bytes).
  - `inputLen`: Length of the input in bytes.
  - `password`: Null-terminated UTF-8 password.
  - `output`: Buffer to store the encrypted data.
  - `maxLen`: Maximum size of the output buffer.
- **Returns**
  - Length of the encrypted data on success.
  - Negative value on failure.

---

### `unsigned char* VTXTSuperSafeText_Decrypt(const unsigned char* data, int length, const char* password, int* outPlainLen)`
Decrypts encrypted data.

- **Parameters**
  - `data`: Pointer to the encrypted data.
  - `length`: Length of the encrypted data in bytes.
  - `password`: Null-terminated UTF-8 password.
  - `outPlainLen`: Pointer to an integer to store the plaintext length.
- **Returns**
  - Pointer to the allocated plaintext buffer (must be freed with `VTXTSuperSafeText_FreeMemory`).
  - `nullptr` if decryption fails.

---

### `void VTXTSuperSafeText_FreeMemory(unsigned char* ptr)`
Frees memory allocated by `VTXTSuperSafeText_Decrypt`.

---

### `int VTXTSuperSafeText_GetVersion(const unsigned char* data, int length)`
Reads the **data format version** from an encrypted buffer.

---

### `unsigned int VTXTSuperSafeText_GetCoreVersion()`
Returns the **core library version** as a packed integer (Major<<16 | Minor<<8 | Patch).

---

### `const char* VTXTSuperSafeText_GetCoreVersionString()`
Returns the **core library version** as a string (e.g., `"3.1.0"`).

---

## Usage in C++

```cpp
#include <iostream>
#include <vector>
#include "VTXTSuperSafeText.h" // header for your DLL

int main() {
    const char* password = "test123";
    const char* message = "Hello world!";
    unsigned char encrypted[1024];

    // Encrypt
    int encLen = VTXTSuperSafeText_Encrypt(
        (const unsigned char*)message,
        strlen(message),
        password,
        encrypted,
        sizeof(encrypted)
    );

    if (encLen > 0) {
        std::cout << "Encrypted length: " << encLen << "\n";

        // Decrypt
        int plainLen = 0;
        unsigned char* decrypted = VTXTSuperSafeText_Decrypt(encrypted, encLen, password, &plainLen);
        if (decrypted) {
            std::string plainText((char*)decrypted, plainLen);
            std::cout << "Decrypted: " << plainText << "\n";
            VTXTSuperSafeText_FreeMemory(decrypted);
        } else {
            std::cout << "Wrong password or corrupted data\n";
        }
    }
}
```

---

## Usage in C#

```csharp
using System;
using System.Runtime.InteropServices;
using System.Text;

class Program
{
    [DllImport("VTXTSuperSafeText.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern int VTXTSuperSafeText_Encrypt(byte[] input, int inputLen, string password, byte[] output, int maxLen);

    [DllImport("VTXTSuperSafeText.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern IntPtr VTXTSuperSafeText_Decrypt(byte[] data, int length, string password, out int outPlainLen);

    [DllImport("VTXTSuperSafeText.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern void VTXTSuperSafeText_FreeMemory(IntPtr ptr);

    static void Main()
    {
        string password = "test123";
        string message = "Hello world!";
        byte[] plainBytes = Encoding.UTF8.GetBytes(message);
        byte[] encrypted = new byte[1024];

        int encLen = VTXTSuperSafeText_Encrypt(plainBytes, plainBytes.Length, password, encrypted, encrypted.Length);
        Console.WriteLine("Encrypted length: " + encLen);

        if (encLen > 0)
        {
            int plainLen;
            IntPtr ptr = VTXTSuperSafeText_Decrypt(encrypted, encLen, password, out plainLen);
            if (ptr != IntPtr.Zero)
            {
                byte[] plainOut = new byte[plainLen];
                Marshal.Copy(ptr, plainOut, 0, plainLen);
                string decrypted = Encoding.UTF8.GetString(plainOut);
                Console.WriteLine("Decrypted: " + decrypted);
                VTXTSuperSafeText_FreeMemory(ptr);
            }
            else
            {
                Console.WriteLine("Wrong password or corrupted data");
            }
        }
    }
}
```

---

## Notes
- Always use UTF-8 encoding for passwords and plaintext.
- The output of `Encrypt` includes:
  ```
  HEADER (4 bytes) + VERSION (4 bytes) + SALT (16 bytes) + IV (16 bytes) + CIPHERTEXT (N bytes)
  ```
- If the format changes in the future, `VTXTSuperSafeText_GetVersion` will help identify which version to use for decryption.
- This library is **not thread-safe** unless you handle locking externally.
