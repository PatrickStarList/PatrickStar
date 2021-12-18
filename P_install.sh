#!/bin/sh

make distclean
autoreconf -ivf --warnings=all

if [ $# -eq 1 -a "$1" = "debug" ]
then
    ./configure --prefix=/opt/PatrickStar --enable-shared --disable-static     --enable-open-appid  --enable-gdb   --enable-debug --enable-reload --enable-file-inspect
else
    ./configure --prefix=/opt/PatrickStar --enable-shared --disable-static  --enable-open-appid   --enable-reload --enable-file-inspect 
fi
make
make install

exit 0;
