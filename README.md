# Oreulius Kernel

Oreulius is a kernel designed to run isolated WASI workloads in a secure operating environment, the kernel is meant to make authority explicit, control access through capabilities on a deep level, and in simple terms, the end goal of developing this is too make sure the behaviour of the workload is incredibly easy to insepct.

<image src="docs/assets/finalized repo image.png"></image>


## How to run

Oreulius is ported to three different architecures, to varying degrees and completeness, those architectures being Aarch64, x86-64, and i686. 

The i686 path is effectively the legacy boot, and its the first boot I created, and did the majority of the early phase of the developement on. Currently, the boot on x86-64 possesses alot of parity with i686, and the Aarch64 has the most work left to do

I personally recommend starting with the i686 boot. These commands will boot it with qemu for you in an easy way to test it and play with it, as its currently in the alpha phase. 

## Required dependencies, environment set up and tool chain

#### 1. Set up environment
#### MACOS
```bash
brew update
brew install qemu llvm binutils coreutils nasm xorriso grub
export PATH="$(brew --prefix llvm)/bin:$PATH"
```
#### Ubuntu/Debian linux
```bash
sudo apt update
sudo apt install -y qemu qemu-system-x86 qemu-system-aarch64 \
  gcc-aarch64-linux-gnu gcc-multilib binutils-aarch64-linux-gnu \
  llvm lld clang build-essential nasm xorriso grub-pc-bin
```

### 2. Set up in Rust Toolchain
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
rustup toolchain install nightly-2024-01-01
rustup component add rust-src --toolchain nightly-2024-01-01
rustup target add aarch64-unknown-none x86_64-unknown-none i686-unknown-none --toolchain nightly-2024-01-01
```


### i686 boot

```bash
cd kernel
./build.sh
./run.sh
```

### x86-64 boot
```bash
cd kernel
./build-x86_64-mb2-iso.sh
./run-x86_64-mb2-grub.sh
```
### If you already have the ISO, use this command to run it in qemu directly for x86-64
```bash
qemu-system-x86_64 -cdrom target/x86_64-mb2/oreulius-x86_64-mb2.iso -serial stdio
```

### Aarch64 boot
```bash
cd kernel
./build-aarch64-virt.sh
./run-aarch64-virt-image.sh
```

### Booting Aarch64 on the virtio block

```bash
# default
./run-aarch64-virt-image-virtio-blk-mmio.sh

# customize disk
BUS_SLOT=1 DISK_IMAGE=target/aarch64-virt/mydisk.img DISK_SIZE=64M ./run-aarch64-virt-image-virtio-blk-mmio.sh
```

### Online Playground
Or alternatively; you can just try a live no install boot on the site: https://www.oreulius.com/try

## Want to run a demo? 

There are a few demos to try in the WASM directory in the root of Oreulius, to help clarify how running a wasm workload will work in the kernel, here is step by step instructions to running one of these demos. For this instruction set lets start with the spawn_children.wat demo,  this script spawns two child WASM processes and prints the respective output. 

#### Step 1
Build the demo
```bash
cd wasm
./build.sh spawn_children.wat
```

#### Step 2
Build the kernel (for this demo lets use the x86_64 image)
```bash
cd ../kernel
./build-x86_64-full.sh
```

#### Step 3 
Package and bundle the kernel together with the demo into an ISO.

  Do this from repo root (or inside kernel)
```bash
mkdir -p kernel/target/x86_64-mb2/iso/boot/grub kernel/target/x86_64-mb2/iso/wasm
cp kernel/target/x86_64-mb2/oreulius-kernel-x86_64 kernel/target/x86_64-mb2/iso/boot/oreulius-kernel-x86_64
cp wasm/spawn_children.wasm kernel/target/x86_64-mb2/iso/wasm/

cat > kernel/target/x86_64-mb2/iso/boot/grub/grub.cfg <<'EOF'
set timeout=0
set default=0
terminal_output console

menuentry "Oreulius x86_64 MB2" {
    multiboot2 /boot/oreulius-kernel-x86_64
    boot
}
EOF
```
Create the ISO (requires grub-mkrescue / xorriso)
```bash
grub-mkrescue -o kernel/target/x86_64-mb2/oreulius-x86_64-mb2.iso kernel/target/x86_64-mb2/iso

```

#### Step 4
boot the iso with qemu to see the live iso running your WASM workload
```bash
cd kernel
./run-x86_64-mb2-grub.sh
```

#### Step 5
Inside the kernel you now have full control to run the demo, track it, with tightened temporal replay, can send it through the peer to capability peer network called capnet, and it is securely sandboxed.

(The kernel is in Alpha, so its not production ready, but that is the idea behind how this kernel works, by taking your WASM workload outside the tech-stack and your existing development environment and operating system, and giving you tight and secure control over the instance). the way a unikernel should be designed, for micro purposes. It could even be used to have tighter analytical and security within other megasecure kernels like sel-4, or to boost features and abilities without sacrificing the security you like of your exisitng operating system

```bash
wasm /wasm/spawn_children.wasm
```

## The guest side SDK for your own app development

To develop your own applicaitons for oreulius, the best place to develop them is in the sdk folder in the wasm folder from the root. 

Located here: 
```
cd wasm/sdk
```

### Dev cycle commands 
For your sdk-based applications
```bash
cd wasm/sdk
cargo build --target wasm32-wasi --release
```
Output:
```
target/wasm32-wasi/release/<your_crate>.wasm
```

to auther tests in wat and compile run this command
```
cd wasm
./build.sh your.wat #application
```

The SDK's are compiled seperately from the kernel, and are not linked. the root wasm folder is for convienient and tiny tests, and the SDK folder is for richer rust/wasm workloads



Thanks, 
Keefe! 


