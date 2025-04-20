# Reverse Engineering Tutorial: Scripts and Practical Examples

## Choosing Languages for Reverse Engineering

The best languages for reverse engineering are:

- **Python** - Best for automation, analysis scripts, and tool development
- **C/C++** - Essential for understanding low-level code and binary analysis
- **Assembly (x86/ARM)** - Critical for disassembly and malware analysis
- **JavaScript** - For web application and Electron app reversing
- **Java/Kotlin** - For Android reverse engineering

## Python Script for Basic Reverse Engineering Tasks

```python
#!/usr/bin/env python3
"""
Reverse Engineering Toolkit (Basic)
"""
import pefile
import capstone
import hashlib
import argparse
from pprint import pprint

def analyze_pe(file_path):
    """Analyze Portable Executable (PE) files"""
    print(f"\n[+] Analyzing PE file: {file_path}")
    
    try:
        pe = pefile.PE(file_path)
        
        # Basic PE information
        print("\nPE Header Information:")
        print(f"  Machine Type: {pe.FILE_HEADER.Machine}")
        print(f"  Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        print(f"  Entry Point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}")
        
        # Imports analysis
        print("\nImport Table:")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"  {entry.dll.decode()}")
            for imp in entry.imports:
                if imp.name:
                    print(f"    - {imp.name.decode()}")
        
        # Calculate hashes
        print("\nFile Hashes:")
        with open(file_path, 'rb') as f:
            data = f.read()
            print(f"  MD5:    {hashlib.md5(data).hexdigest()}")
            print(f"  SHA1:   {hashlib.sha1(data).hexdigest()}")
            print(f"  SHA256: {hashlib.sha256(data).hexdigest()}")
        
        # Disassemble code section
        print("\nDisassembly of Code Section:")
        code_section = next((s for s in pe.sections if s.Name.decode().strip('\x00') == '.text'), None)
        if code_section:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            for i in md.disasm(code_section.get_data(), code_section.VirtualAddress):
                print(f"0x{i.address:08x}: {i.mnemonic}\t{i.op_str}")
        
    except Exception as e:
        print(f"Error analyzing PE file: {e}")
    finally:
        pe.close()

def strings_extraction(file_path, min_length=4):
    """Extract ASCII strings from binary"""
    print(f"\n[+] Extracting strings from: {file_path}")
    with open(file_path, 'rb') as f:
        result = ""
        for char in f.read():
            if 32 <= char <= 126:
                result += chr(char)
            else:
                if len(result) >= min_length:
                    print(result)
                result = ""

def main():
    parser = argparse.ArgumentParser(description="Basic Reverse Engineering Toolkit")
    parser.add_argument("file", help="File to analyze")
    parser.add_argument("-s", "--strings", action="store_true", help="Extract strings")
    args = parser.parse_args()
    
    if args.strings:
        strings_extraction(args.file)
    else:
        analyze_pe(args.file)

if __name__ == "__main__":
    main()
```

## Example: Reverse Engineering a Simple C Program
### 1. Target Program (simple_crackme.c)
```c
#include <stdio.h>
#include <string.h>

int check_password(const char* password) {
    const char* secret = "s3cr3t";
    return strcmp(password, secret) == 0;
}

int main() {
    char input[32];
    printf("Enter password: ");
    scanf("%31s", input);
    
    if (check_password(input)) {
        printf("Access granted!\n");
    } else {
        printf("Access denied!\n");
    }
    
    return 0;
}
```
### 2. Compile the Program
```bash
gcc simple_crackme.c -o crackme -m32  # Compile as 32-bit for easier analysis
```
### 3. Analysis Steps
Static Analysis with Radare2
```bash
r2 -AAA crackme
> afl                 # List functions
> s main              # Seek to main
> pdf                 # Disassemble main
> s sym.check_password
> pdf
```
Dynamic Analysis with GDB
```bash
gdb ./crackme
(gdb) break check_password
(gdb) run
(gdb) x/s $esp+4     # View password argument
(gdb) disassemble
```
Python Script to Find Password
```python
#!/usr/bin/env python3
from pwn import *

def find_password():
    # Static analysis approach
    elf = ELF('./crackme')
    
    # Find all strings in the binary
    for addr, string in elf.strings().items():
        if len(string) >= 4 and string.isprintable():
            print(f"Potential password at 0x{addr:x}: {string}")
    
    # Alternative: brute-force the check function
    context.log_level = 'error'
    p = process('./crackme')
    
    with open('/usr/share/dict/words', 'r') as f:
        for word in f:
            word = word.strip()
            p.sendline(word)
            output = p.recvline()
            if b'granted' in output:
                print(f"Found password: {word}")
                break
    p.close()

if __name__ == "__main__":
    find_password()
```
## Reverse Engineering Android APK
### Tools Needed:
- apktool - Decompile APK to smali

- dex2jar - Convert DEX to JAR

- jd-gui - View Java source

- frida - Dynamic instrumentation

Example Workflow:
```bash
# Decompile APK
apktool d target.apk -o output_dir

# Extract classes.dex and convert to JAR
d2j-dex2jar.sh target.apk

# Analyze with JD-GUI
jd-gui classes-dex2jar.jar

# Dynamic analysis with Frida
frida -U -l script.js -f com.example.app --no-pause
```
Frida Script Example (script.js):
```javascript
Java.perform(function() {
    // Hook a method to log arguments and return value
    var targetClass = Java.use("com.example.app.AuthHelper");
    
    targetClass.checkPassword.implementation = function(password) {
        console.log("checkPassword called with: " + password);
        var result = this.checkPassword(password);
        console.log("Result: " + result);
        return result;
    };
    
    // Bypass certificate pinning
    var TrustManager = Java.use('javax.net.ssl.TrustManager');
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    
    var TrustManagerFactory = Java.registerClass({
        name: 'com.example.TrustManagerFactory',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function() { console.log("Bypassing client trust"); },
            checkServerTrusted: function() { console.log("Bypassing server trust"); },
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', 
                            '[Ljavax.net.ssl.TrustManager;', 
                            'java.security.SecureRandom').implementation = function() {
        console.log("SSLContext.init() hooked");
        this.init(arguments[0], [TrustManagerFactory.$new()], arguments[2]);
    };
});
```
Reverse Engineering Web Applications
JavaScript Deobfuscation Example
Original obfuscated code:

```javascript
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1.0(\'3 2!\');',4,4,'log|console|World|Hello'.split('|'),0,{}))
```
Deobfuscated code:

```javascript
console.log('Hello World!');
```
Python Deobfuscation Script:
```python
import jsbeautifier

def deobfuscate_js(code):
    try:
        # Try to beautify first
        beautified = jsbeautifier.beautify(code)
        
        # If it contains eval, try to unpack
        if 'eval(' in beautified:
            # Simple unpacker for common patterns
            if beautified.startswith('eval(function(p,a,c,k,e,d)'):
                # This is packed with Dean Edwards' packer
                unpacked = code.replace('eval', 'console.log')
                try:
                    unpacked = eval(unpacked)
                    return unpacked
                except:
                    pass
        
        return beautified
    except Exception as e:
        print(f"Deobfuscation error: {e}")
        return code

# Example usage
obfuscated = "eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1.0(\'3 2!\');',4,4,'log|console|World|Hello'.split('|'),0,{}))"
print(deobfuscate_js(obfuscated))
```
## Good Practices in Reverse Engineering
### Documentation:
Keep detailed notes of your findings

Document function calls, parameters, and return values

Create call graphs and control flow diagrams

### Analysis Techniques:
Start with static analysis before dynamic analysis

Use both high-level (source code) and low-level (assembly) analysis

Compare behavior across different environments

### Tool Usage:
Use version control for your analysis scripts

Automate repetitive tasks with scripts

Combine multiple tools for cross-verification

### Ethical Considerations:
Only reverse engineer software you own or have permission to analyze

Respect copyright laws and EULAs

Report vulnerabilities responsibly

### Security:
Analyze malware in isolated environments

Use VM snapshots for dynamic analysis

Never run unknown code on production systems

Learning Resources
### Books:
"Practical Reverse Engineering" by Bruce Dang

"The IDA Pro Book" by Chris Eagle

"Reverse Engineering for Beginners" by Dennis Yurichev (free PDF)

### Online Courses:
OpenSecurityTraining.info

Malware Unicorn RE101

Pentester Academy Reverse Engineering courses

### Practice Platforms:
Crackmes.one

Hack The Box reversing challenges

Reverse Engineering challenges on CTF platforms

### Communities:
/r/ReverseEngineering on Reddit

Reverse Engineering Stack Exchange

Various Discord and Telegram groups

This tutorial provides a comprehensive starting point for reverse engineering across different platforms. Remember that reverse engineering is a skill developed over time with practice across many different targets.

