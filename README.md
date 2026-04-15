# Oreulius Kernel

Oreulius is a kernel designed to run isolated WASI workloads in a secure operating environment, the kernel is meant to make authority explicit, control access through capabilities on a deep level, and in simple terms, the end goal of developing this is too make sure the behaviour of the workload is incredibly easy to insepct.

<image src="docs/assets/finalized repo image.png"></image>


## How to run

Oreulius is ported to three different architecures, to varying degrees and completeness, those architectures being Aarch64, x86-64, and i686. 

The i686 path is effectively the legacy boot, and its the first boot I created, and did the majority of the early phase of the developement on. Currently, the boot on x86-64 possesses alot of parity with i686, and the Aarch64 has the most work left to do

I personally recommend starting with the i686 boot. These commands will boot it with qemu for you in an easy way to test it and play with it, as its currently in the alpha phase. 

### Required dependencies, environment set up and tool chain

#### 1. Set up environment
#### MACOS
```
brew update
brew install qemu llvm binutils coreutils nasm xorriso grub
export PATH="$(brew --prefix llvm)/bin:$PATH"
```
#### Ubuntu/Debian linux
```
sudo apt update
sudo apt install -y qemu qemu-system-x86 qemu-system-aarch64 \
  gcc-aarch64-linux-gnu gcc-multilib binutils-aarch64-linux-gnu \
  llvm lld clang build-essential nasm xorriso grub-pc-bin
```

### 2. Set up in Rust Toolchain
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
rustup toolchain install nightly-2024-01-01
rustup component add rust-src --toolchain nightly-2024-01-01
rustup target add aarch64-unknown-none x86_64-unknown-none i686-unknown-none --toolchain nightly-2024-01-01
```


### i686 boot

```
cd kernel
./build.sh
./run.sh
```

### x86-64 boot
```
cd kernel
./build-x86_64-mb2-iso.sh
./run-x86_64-mb2-grub.sh
```
### If you already have the ISO, use this command to run it in qemu directly for x86-64
```
qemu-system-x86_64 -cdrom target/x86_64-mb2/oreulius-x86_64-mb2.iso -serial stdio
```

### Aarch64 boot
```
cd kernel
./build-aarch64-virt.sh
./run-aarch64-virt-image.sh
```

### Booting Aarch64 on the virtio block

```
# default
./run-aarch64-virt-image-virtio-blk-mmio.sh

# customize disk
BUS_SLOT=1 DISK_IMAGE=target/aarch64-virt/mydisk.img DISK_SIZE=64M ./run-aarch64-virt-image-virtio-blk-mmio.sh
```

### Online Playground
Or alternatively; you can just try a live no install boot on the site: https://www.oreulius.com/try

### Want to run a demo? 

There are a few demos to try in the WASM directory in the root of Oreulius, to help clarify how running a wasm workload will work in the kernel, here is step by step instructions to running one of these demos. For this instruction set lets start with the spawn_children.wat demo,  this script spawns two child WASM processes and prints the respective output. 

#### Step 1
Build the demo
```
cd wasm
./build.sh spawn_children.wat
```

#### Step 2
Build the kernel (for this demo lets use the x86_64 image)
```
cd ../kernel
./build-x86_64-full.sh
```

#### Step 3 
Package and bundle the kernel together with the demo into an ISO.

  Do this from repo root (or inside kernel)
```
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
```
grub-mkrescue -o kernel/target/x86_64-mb2/oreulius-x86_64-mb2.iso kernel/target/x86_64-mb2/iso

```

#### Step 4
boot the iso with qemu to see the live iso running your WASM workload
```
cd kernel
./run-x86_64-mb2-grub.sh
```

#### Step 5
inside the kernel you now have full control to run the demo, track it, with tightened temporal replay, can send it through the peer to capability peer network called capnet, and it is securely sandboxed.

(The kernel is in Alpha, so its not production ready, but that is the idea behind how this kernel works, by taking your WASM workload outside the kernel and giving you tight and secure control over it)

```
wasm /wasm/spawn_children.wasm
```


Thanks, 
Keefe! 


