#!/usr/bin/bash

# This script clones, builds, and installs Python bindings for GPG
# It was tested on Fedora Server 43

set -x

sudo dnf check-update

set -e

sudo dnf -y upgrade
sudo dnf -y install git gcc autoconf automake python3-devel gnupg2-smime texinfo pandoc swig gettext

pip install --upgrade pip
pip install setuptools
pip install websockets
pip install --upgrade setuptools


# Check if libgpg-error is not already installed
if [[ -z $(ls /usr/local/lib/libgpg-error.so*) ]]; then
    git clone git://git.gnupg.org/libgpg-error.git
    pushd libgpg-error
    ./autogen.sh
    ./configure --enable-maintainer-mode && make
    sudo make install
    popd
    sudo rm -rf libgpg-error
fi


# Check if libassuan is not already installed
if [[ -z $(ls /usr/local/lib/libassuan.so*) ]]; then
    git clone git://git.gnupg.org/libassuan.git
    pushd libassuan
    ./autogen.sh
    ./configure --enable-maintainer-mode && make
    sudo make install
    popd
    sudo rm -rf libassuan
fi


# Check if gpgme is not already installed
if [[ -z $(ls /usr/local/lib/libgpgme.so*) ]]; then
    git clone git://git.gnupg.org/gpgme.git
    pushd gpgme
    ./autogen.sh
    mkdir build && cd build && ../configure --enable-maintainer-mode && make
    sudo make install
    popd
    sudo rm -rf gpgme
fi


# Check if gpgmepy is not already installed
if [[ -z $(ls /usr/local/lib64/python3*/site-packages/gpg*.egg) ]]; then
    git clone git://git.gnupg.org/gpgmepy.git
    pushd gpgmepy
    ./autogen.sh
    mkdir build && cd build && ../configure --enable-maintainer-mode && make
    sudo make install
    popd
    sudo rm -rf gpgmepy
fi


set +x

# Check if gpg can be imported in python
if [[ ! -z $(python3 -c "import gpg" 2>&1) ]]; then
    echo ""
    echo "[ERROR] Could not 'import gpg'"
    echo "Make sure to:"
    echo "  export LD_LIBRARY_PATH=/usr/local/lib/"
    exit 1
else
    echo ""
    echo "Huzzah!"
fi

