<<<<<<< HEAD
# Rust SymCrypt

## THIS IS A WIP!!!
=======
Introduction

Within this repo there are two crates:
1. symcrypt-sys; very basic Rust/C FFI bindings over top of SymCrypt using bindgen
2. rust-symcrypt; which provides friendly rust wrappers over top of symcrypt-sys

The purpose of these set of crates is to bring FIPS compliant cryptography to the Rust Ecosystem. Currently there is only binding support for 
Windows and Linux. 


Prerequisites: 

1. clang https://rust-lang.github.io/rust-bindgen/requirements.html 
    Windows: winget install LLVM.LLVM
    Linux: apt install llvm-dev libclang-dev clang

2. Cmake 
    Windows: Visual studio enterpise ( don't need to activate trial, just need enterprise build tools ): https://visualstudio.microsoft.com/downloads/
    also set path: $env:PATH="C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\;${env:PATH}"
    Linux: sudo apt install cmake

3. Python 3 / pip3
    Windows: python -m pip3 install --upgrade pip
    Linux: apt install -f python3-pip 

4. 



If you are on Windows:

1. Clone repo:
    git clone git@github.com:nnmkhang/rust-symcrypt-sys.git

    You might run into errors with errors if you are using ssh, follow this guide to fix issues:https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent

2. navigate into the root of the repo 
    cd rust-symcrypt-sys/

3. Get SymCrypt submodule: 
    git submodule update --init SymCrypt

4. Navigate to SymCrypt directory 
    cd SymCrypt

5. Get third party need requirments:
    pip3 install -r ./scripts/requirements.txt
    git submodule update --init -- 3rdparty/jitterentropy-library

6. Build SymCrypt
    cmake -S . -B bin
    cmake --build bin

7. Move:
    Move-Item -Path ".\bin\exe\symcrypttestmodule.dll" -Destination "C:\Windows\System32"






If you are on linux / WSL :

From Fresh WSL install:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt install cargo
sudo apt install cmake
sudo apt install -f python3-pip 
sudo apt install llvm-dev libclang-dev clang



Installation steps:

1. Clone repo:
    git clone git@github.com:nnmkhang/rust-symcrypt-sys.git

    You might run into errors with errors if you are using ssh, follow this guide to fix issues:https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent

2. navitage into the root of the repo 
    cd rust-symcrypt-sys/

3. Get symcrypt dependancy: 
    git submodule update --init SymCrypt

4. Navigate to SymCrypt directory 
    cd SymCrypt

5. Get third party need requirments:
    sudo apt install -f python3-pip 
    pip3 install -r ./scripts/requirements.txt
    git submodule update --init -- 3rdparty/jitterentropy-library

6. Build SymCrypt
    cmake -S . -B bin
    cmake --build bin

7. Move lib files

8. Run cargo build 
    cd symcrypt-sys
    sudo apt install llvm-dev libclang-dev clang ( if not already done)
    cargo build
    

9. Move lib symcrypt files to root directory
    sudo mv ./bin/module/generic/libsymcrypt.so* /lib/x86_64-linux-gnu/ 
    SymCrypt/bin/module/generic ( sudo needed to move to lib folder)




3. Verify that everything is working
    cd ../rust-symcrypt
    cargo test
    if it does not fail it works (yay)








!!! notes for tom> for some reason its looking for lsymcrypttestmodule? Idk why....








Notes on FIPs compliance: 



>>>>>>> 659ade3a9d951f73ebf2ed036c9ff72c3e60df99

## Introduction

Within this repository, there are two crates:

1. **symcrypt-sys**: Very basic Rust/C FFI bindings over SymCrypt using bindgen.
2. **rust-symcrypt**: Provides friendly Rust wrappers over `symcrypt-sys`.

The purpose of these crates is to bring FIPS-compliant cryptography to the Rust Ecosystem. Currently, there is only binding support for Windows and Linux.

## Prerequisites

Before getting started, ensure you have the following prerequisites installed:

1. **Clang**:
   - Windows: `winget install LLVM.LLVM`
   - Linux: `apt install llvm-dev libclang-dev clang`

2. **CMake**:
   - Windows: Visual Studio Enterprise (no need to activate trial, just need enterprise build tools). [Download](https://visualstudio.microsoft.com/downloads/)
     - Also, set the PATH: `$env:PATH="C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\;${env:PATH}"`
   - Linux: `sudo apt install cmake`

3. **Python 3 / pip3**:
   - Windows: `python -m pip3 install --upgrade pip`
   - Linux: `apt install -f python3-pip`

### Windows Instructions

1. Clone the repo:  

`git clone git@github.com:nnmkhang/rust-symcrypt-sys.git`   

You might run into errors with errors if you are using ssh, follow this guide to fix issues: [link](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent)

2. navigate into the root of the repo  
    `cd rust-symcrypt-sys/`

3. Get SymCrypt submodule    
    `git submodule update --init SymCrypt` 

4. Navigate to SymCrypt directory   
    `cd SymCrypt`

5. Get third party need requirements      
    `pip3 install -r ./scripts/requirements.txt`     
    `git submodule update --init -- 3rdparty/jitterentropy-library`

6. Build SymCrypt  
    `cmake -S . -B bin`
    `cmake --build bin`

7. Move:  
    `Move-Item -Path ".\bin\exe\symcrypttestmodule.dll" -Destination "C:\Windows\System32"`

8. Run cargo build   
    `cd symcrypt-sys`
    `cargo build`
    

9. Verify that everything is working  
    `cd ../rust-symcrypt`
    `cargo test`




### WSL / Linux Instructions

From Fresh WSL install, you must install the following   

1. `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
2. `sudo apt install cargo`
3. `sudo apt install cmake`
4. `sudo apt install -f python3-pip`
5. `sudo apt install llvm-dev libclang-dev clang`

Installation steps  

1. Clone repo     
    `git clone git@github.com:nnmkhang/rust-symcrypt-sys.git`

    You might run into errors with errors if you are using ssh, follow this guide to fix issues. [link](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent)

2.  Navigate into the root of the repo    
    `cd rust-symcrypt-sys/`

3. Get symcrypt dependency    
    `git submodule update --init SymCrypt`

4. Navigate to SymCrypt directory     
    `cd SymCrypt`

5. Get third party need requirements  
    `pip3 install -r ./scripts/requirements.txt`    
    `git submodule update --init -- 3rdparty/jitterentropy-library`

6. Build SymCrypt  
    `cmake -S . -B bin`
    `cmake --build bin`

7. Move lib symcrypt files to root directory  
    `sudo mv ./bin/module/generic/libsymcrypt.so* /lib/x86_64-linux-gnu/`

8. Run cargo build   
    `cd symcrypt-sys`  
    `cargo build`
    

9. Verify that everything is working  
    `cd ../rust-symcrypt`  
    `cargo test`
    
