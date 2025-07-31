# VTXTSuperSafeText

VTXTSuperSafeText is an **open-source** high-security text encryption library written in C++ using OpenSSL.  
It supports **AES‑256‑CBC** encryption with PBKDF2 key derivation and a custom binary format:  

```
[HEADER:4 bytes] [VERSION:4 bytes] [SALT:16 bytes] [IV:16 bytes] [CIPHERTEXT:variable]
```

The library is cross-platform (Windows / Linux / macOS) and can be used from **C++**, **C#**, **Python**, **Java**, and other languages that support native libraries.

Licensed under the **MIT License**.

---

## Features
- AES‑256‑CBC encryption with PKCS#5 padding.
- PBKDF2-HMAC-SHA256 key derivation (500,000 iterations).
- Custom binary header with versioning.
- Open-source and cross-platform.
- API designed for multi-language usage.

---

## Download

Prebuilt binaries are available on the **[GitHub Releases](https://github.com/yourusername/VTXTSuperSafeText/releases/latest)** page.

**Example:**
- Windows: `VTXTSuperSafeText.dll`
- Linux: `libVTXTSuperSafeText.so`
- macOS: `libVTXTSuperSafeText.dylib`

> For smallest size, files are compressed in `.7z` format. Extract using [7-Zip](https://www.7-zip.org/) or WinRAR.

---

## Build from source

### Requirements
- CMake 3.10+
- OpenSSL development libraries
- C++17 compiler

### Build steps
```bash
git clone https://github.com/yourusername/VTXTSuperSafeText.git
cd VTXTSuperSafeText
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

---

## API

### Encrypt
```cpp
int VTXTSuperSafeText_Encrypt(
    const unsigned char* input,
    int inputLen,
    const char* password,
    unsigned char* output,
    int maxLen
);
```
Returns the total output length, or a negative value on error.

### Decrypt
```cpp
unsigned char* VTXTSuperSafeText_Decrypt(
    const unsigned char* data,
    int length,
    const char* password,
    int* outPlainLen
);
```
Returns allocated plaintext buffer. Must be freed with `VTXTSuperSafeText_FreeMemory`.

### Free memory
```cpp
void VTXTSuperSafeText_FreeMemory(unsigned char* ptr);
```

### Get version
```cpp
int VTXTSuperSafeText_GetVersion(const unsigned char* data, int length);
```

---

## Usage Examples

### C++
```cpp
#include "VTXTSuperSafeText.h"
#include <vector>
#include <iostream>

int main() {
    const char* text = "Hello World!";
    const char* password = "mypassword";
    std::vector<unsigned char> encrypted(1024);

    int encLen = VTXTSuperSafeText_Encrypt(
        (const unsigned char*)text, strlen(text),
        password, encrypted.data(), encrypted.size()
    );

    if (encLen > 0) {
        int plainLen = 0;
        unsigned char* decrypted = VTXTSuperSafeText_Decrypt(
            encrypted.data(), encLen, password, &plainLen
        );

        if (decrypted) {
            std::string result((char*)decrypted, plainLen);
            std::cout << "Decrypted: " << result << "\n";
            VTXTSuperSafeText_FreeMemory(decrypted);
        }
    }
}
```

---

### C# (P/Invoke)
```csharp
[DllImport("VTXTSuperSafeText.dll", CallingConvention = CallingConvention.Cdecl)]
public static extern int VTXTSuperSafeText_Encrypt(
    byte[] input, int inputLen,
    string password,
    byte[] output, int maxLen
);

[DllImport("VTXTSuperSafeText.dll", CallingConvention = CallingConvention.Cdecl)]
public static extern IntPtr VTXTSuperSafeText_Decrypt(
    byte[] data, int length,
    string password,
    out int outPlainLen
);

[DllImport("VTXTSuperSafeText.dll", CallingConvention = CallingConvention.Cdecl)]
public static extern void VTXTSuperSafeText_FreeMemory(IntPtr ptr);

// Example usage
byte[] plain = Encoding.UTF8.GetBytes("Hello World!");
byte[] encrypted = new byte[1024];
int encLen = VTXTSuperSafeText_Encrypt(plain, plain.Length, "mypassword", encrypted, encrypted.Length);

IntPtr ptr = VTXTSuperSafeText_Decrypt(encrypted, encLen, "mypassword", out int plainLen);
if (ptr != IntPtr.Zero) {
    byte[] plainOut = new byte[plainLen];
    Marshal.Copy(ptr, plainOut, 0, plainLen);
    string result = Encoding.UTF8.GetString(plainOut);
    Console.WriteLine("Decrypted: " + result);
    VTXTSuperSafeText_FreeMemory(ptr);
}
```

---

### Python (ctypes)
```python
import ctypes

lib = ctypes.CDLL("./VTXTSuperSafeText.dll")
lib.VTXTSuperSafeText_Encrypt.argtypes = [
    ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
    ctypes.c_char_p, ctypes.c_int
]

lib.VTXTSuperSafeText_Decrypt.argtypes = [
    ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_int)
]
lib.VTXTSuperSafeText_Decrypt.restype = ctypes.c_void_p

lib.VTXTSuperSafeText_FreeMemory.argtypes = [ctypes.c_void_p]

text = b"Hello World!"
password = b"mypassword"
encrypted = ctypes.create_string_buffer(1024)

enc_len = lib.VTXTSuperSafeText_Encrypt(text, len(text), password, encrypted, len(encrypted))

out_len = ctypes.c_int()
ptr = lib.VTXTSuperSafeText_Decrypt(encrypted, enc_len, password, ctypes.byref(out_len))

if ptr:
    buf = ctypes.create_string_buffer(out_len.value)
    ctypes.memmove(buf, ptr, out_len.value)
    print("Decrypted:", buf.raw.decode())
    lib.VTXTSuperSafeText_FreeMemory(ptr)
```

---

### Java (JNI)
```java
public class VTXT {
    static {
        System.loadLibrary("VTXTSuperSafeText");
    }
    public native int VTXTSuperSafeText_Encrypt(byte[] input, int inputLen, String password, byte[] output, int maxLen);
    public native long VTXTSuperSafeText_Decrypt(byte[] data, int length, String password, int[] outPlainLen);
    public native void VTXTSuperSafeText_FreeMemory(long ptr);
}
```

---

## License
MIT License – see [LICENSE](LICENSE) for details.
