set -ex

# Install deps
pip3 install meson ninja meson-python

if command -v apt; then
    apt update && apt install --assume-yes libclang-7-dev clang-7 llvm-7
elif command -v apk; then
    apk update && apk add clang-dev
fi

# Install rizin
git clone --depth 1 https://github.com/wingdeans/rizin.git -b header-types
pushd rizin

if [[ "$OSTYPE" =~ msys* ]]; then
    meson setup --prefix='c:/rizin' --vsenv build
else
    meson setup --libdir=lib build
fi

meson install -C build
popd