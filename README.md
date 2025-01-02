# SeBPFile

**SeBPFile** (pronounced **Seb-file**) is an eBPF-based security solution that uses TPM2 (Trusted Platform Module 2.0) for enhanced protection of secret files. It combines real-time monitoring via eBPF, transparent encryption using ChaCha20, and access control to ensure sensitive data is protected from unauthorized access, even in scenarios involving physical access to the system.

### Why the name **SeBPFile**?

The name reflects the core focus of the project:

- **"Se"**: Suggests security or being secure, the primary goal of the project.
- **"BPF"**: Highlights the use of eBPF, the cutting-edge technology at the heart of the solution.
- **"File"**: Directly ties the project to file management and protection.

## Features

- **eBPF-powered Monitoring**: Uses eBPF to monitor system calls related to file access and detect abnormal behavior in real-time.
- **ChaCha20 Encryption**: Implements ChaCha20 encryption to securely encrypt files at rest, offering a fast and secure encryption method.
- **Transparent Encryption**: Automatically encrypts and decrypts files without requiring user intervention, providing seamless protection.
- **TPM2 Integration**: Leverages TPM2 for secure key storage and management, ensuring that encryption keys are securely stored in hardware, preventing extraction.
- **Physical Access Protection**: Prevents data leaks even in the case of physical access to the machine, similar to LUKS encryption, by using TPM2 for key management.
- **Simple Access Control**: Defines file access policies to restrict access based on user, process, or context.

## Installation (Arch Linux)

1. Clone the repository with submodules:

   ```bash
   git clone --recurse-submodules https://github.com/hitori1403/SeBPFile.git
   cd SeBPFile
   ```

2. Install dependencies:

   ```bash
   sudo pacman -S clang gcc make tpm2-tools libyaml
   ```

3. Compile the project:
   ```bash
   make
   ```

## How it works

SeBPFile operates by hooking into file-related syscalls such as `open`, `read`, `write`, and `lseek`. When these syscalls are invoked, SeBPFile intercepts them and performs encryption or decryption operations before the data is either stored to disk or given to the application. This approach ensures that the file contents are always encrypted at rest, and only authorized processes can access the decrypted content based on the defined access control policies.

The encryption uses the ChaCha20 algorithm for its speed and security, while TPM2 is employed for secure key management, ensuring the keys are never exposed to unauthorized parties, even during physical access to the system.

## Usage

1. **Initialize TPM**:
   Run the following command to initialize TPM with `sudo`:

   ```bash
   sudo ./init
   ```

2. **Prepare `rules.yml`**:
   Create and configure the `rules.yml` file to define the access control policies for protecting secret files. Example:

   ```yaml
   rules:
     - /tmp/secret: # Secret file to protect
         - /usr/bin/cat: # Process to monitor access to the secret file
             user: hitori
             perm: rw # Read and write permissions
         - /usr/bin/nvim: # Another process to monitor
             user: hitori
             pid: 2
             ppid: 1
   ```

   In this example:

   - **/tmp/secret** is the secret file that needs to be protected.
   - **/usr/bin/cat** is the process that will be monitored for access to the secret file. The user **hitori** is granted read and write (`rw`) permissions.
   - **/usr/bin/nvim** is another process that will be monitored. The user **hitori** with **pid: 2** and **ppid: 1** will be allowed to access the file.

3. **Run SeBPFile**:
   Once you have initialized TPM and prepared the `rules.yml` file, run the following command to start SeBPFile with `sudo`:
   ```bash
   sudo ./main
   ```
