#!/bin/bash
# Usage: build-test.sh [ubuntu-21.04|ubuntu-20.04|ubuntu-18.04|alpine-3.14|fedora-34]...
# Environment variables
# - IMAGE_NAME
BINDIR=$(dirname $(readlink -f $0))
WORKDIR=$(dirname $BINDIR)

ubuntu-18.04() {
    STIME=$(date +%s)
    echo "$(date) Build redbpf with kernel v4.19 headers on Ubuntu 18.04"
    docker run --privileged -v $WORKDIR:/build -w /build $IMAGE_NAME:latest-ubuntu-18.04 /bin/bash -c 'cargo clean && export KERNEL_VERSION=$(ls --indicator-style=none /lib/modules/) && echo KERNEL_VERSION=$KERNEL_VERSION && cargo build && cargo build --examples'
    ERR=$?
    ETIME=$(date +%s)
    echo "took $(((ETIME - STIME) / 60))m$(((ETIME - STIME) % 60))s"
    if [[ $ERR -ne 0 ]]; then
        echo "Failed to build redbpf with kernel headers on Ubuntu 18.04" >&2
        exit 1
    fi

    # NOTE The Linux kernel image of Ubuntu 18.04 does not contain .BTF section. So
    # building redBPF with vmlinux is not tried here.
}

ubuntu-20.04() {
    STIME=$(date +%s)
    echo "$(date) Build redbpf with kernel headers on Ubuntu 20.04"
    docker run --privileged -v $WORKDIR:/build -w /build $IMAGE_NAME:latest-ubuntu-20.04 /bin/bash -c 'cargo clean && export KERNEL_VERSION=$(ls --indicator-style=none /lib/modules/) && echo KERNEL_VERSION=$KERNEL_VERSION && cargo build && cargo build --examples'
    ERR=$?
    ETIME=$(date +%s)
    echo "took $(((ETIME - STIME) / 60))m$(((ETIME - STIME) % 60))s"
    if [[ $ERR -ne 0 ]]; then
        echo "Failed to build redbpf with kernel headers on Ubuntu 20.04" >&2
        exit 1
    fi

    # NOTE The Linux kernel image of Ubuntu 20.04 does not contain .BTF section. So
    # building redBPF with vmlinux is not tried here.
}

ubuntu-21.04() {
    STIME=$(date +%s)
    echo "$(date) Build redbpf with kernel headers on Ubuntu 21.04"
    docker run --privileged -v $WORKDIR:/build -w /build $IMAGE_NAME:latest-ubuntu-21.04 /bin/bash -c 'cargo clean && export KERNEL_VERSION=$(ls --indicator-style=none /lib/modules/) && echo KERNEL_VERSION=$KERNEL_VERSION && cargo build && cargo build --examples --features=kernel5_8'
    ERR=$?
    ETIME=$(date +%s)
    echo "took $(((ETIME - STIME) / 60))m$(((ETIME - STIME) % 60))s"
    if [[ $ERR -ne 0 ]]; then
        echo "Failed to build redbpf with kernel headers on Ubuntu 21.04" >&2
        exit 1
    fi

    STIME=$(date +%s)
    echo "$(date) Build redbpf wih vmlinux on Ubuntu 21.04"
    docker run --privileged -v $WORKDIR:/build -w /build $IMAGE_NAME:latest-ubuntu-21.04 /bin/bash -c 'cargo clean && /lib/modules/*/build/scripts/extract-vmlinux /boot/vmlinuz > /boot/vmlinux && export REDBPF_VMLINUX=/boot/vmlinux && cargo build && cargo build --examples --features=kernel5_8'
    ERR=$?
    ETIME=$(date +%s)
    echo "took $(((ETIME - STIME) / 60))m$(((ETIME - STIME) % 60))s"
    if [[ $ERR -ne 0 ]]; then
        echo "Failed to build redbpf with vmlinux on Ubuntu 21.04" >&2
        exit 1
    fi
}

alpine-3.14() {
    STIME=$(date +%s)
    echo "$(date) Build redbpf wih kernel headers on Alpine 3.14"
    docker run --privileged -v $WORKDIR:/build -w /build $IMAGE_NAME:latest-alpine sh -c 'cargo clean && export KERNEL_VERSION=$(ls --indicator-style=none /lib/modules/) RUSTFLAGS=-Ctarget-feature=-crt-static && echo KERNEL_VERSION=$KERNEL_VERSION && cargo +1.51 build --no-default-features --features llvm11 && cargo +1.51 build --no-default-features --features llvm11 --examples'
    ERR=$?
    ETIME=$(date +%s)
    echo "took $(((ETIME - STIME) / 60))m$(((ETIME - STIME) % 60))s"
    if [[ $ERR -ne 0 ]]; then
        echo "Failed to build redbpf with kernel headers on Alpine 3.14" >&2
        exit 1
    fi

    # NOTE The Linux kernel image of Alpine 3.14 does not contain .BTF section. So
    # building redBPF with vmlinux is not tried here.
}

fedora-34() {
    STIME=$(date +%s)
    echo "$(date) Build redbpf wih kernel headers on Fedora 34"
    docker run --privileged -v $WORKDIR:/build -w /build $IMAGE_NAME:latest-fedora-34 sh -c 'make -C /lib/modules/*/build prepare; cargo clean && export KERNEL_VERSION=$(ls --indicator-style=none /lib/modules/) && echo KERNEL_VERSION=$KERNEL_VERSION && cargo build && cargo build --examples'
    ERR=$?
    ETIME=$(date +%s)
    echo "took $(((ETIME - STIME) / 60))m$(((ETIME - STIME) % 60))s"
    if [[ $ERR -ne 0 ]]; then
        echo "Failed to build redbpf with kernel headers on Fedora 34" >&2
        exit 1
    fi

    STIME=$(date +%s)
    echo "$(date) Build redbpf wih vmlinux on Fedora 34"
    docker run --privileged -v $WORKDIR:/build -w /build $IMAGE_NAME:latest-fedora-34 sh -c 'cargo clean && /lib/modules/*/build/scripts/extract-vmlinux /lib/modules/*/vmlinuz > /boot/vmlinux && export REDBPF_VMLINUX=/boot/vmlinux && cargo build && cargo build --examples'
    ERR=$?
    ETIME=$(date +%s)
    echo "took $(((ETIME - STIME) / 60))m$(((ETIME - STIME) % 60))s"
    if [[ $ERR -ne 0 ]]; then
        echo "Failed to build redbpf with vmlinux on Fedora 34" >&2
        exit 1
    fi
}

if [[ -z $IMAGE_NAME ]]; then
    IMAGE_NAME=ghcr.io/foniod/foniod-build
fi

if [[ $# -eq 0 ]]; then
    TARGETS=all
else
    TARGETS=$@
fi

for TARGET in $TARGETS; do
    case $TARGET in
        all)
            ubuntu-21.04
            ubuntu-20.04
            ubuntu-18.04
            alpine-3.14
            fedora-34
            ;;
        *)
            $TARGET
            ;;
    esac
done
