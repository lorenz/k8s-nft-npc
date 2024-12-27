# k8s-nft-npc
*A Kubernetes Network Policy Controller based on pure nftables*

:warning: This is alpha-level software, no guarantees for functionality or correctness right now.

## Features
* Fully dual-stack (IPv4/IPv6)
* No dependency on anything but the K8s API and the Linux kernel (no nftables CLI or shared linking)
* Event-based, reacts very quickly
* Atomic nftables updates

## Usage
Either run it in a container with host network namespace access or run it as a
separate binary with the `--kubeconfig` option pointing to a valid kubeconfig
to contact the API server. Currently no precompiled binaries are provided,
build them using the standard Go toolchain.
