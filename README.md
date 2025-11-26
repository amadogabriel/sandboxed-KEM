# PQC sealed box (liboqs + OpenSSL)
Build: cc -O2 pqc_box.c $(pkg-config --cflags --libs liboqs openssl) -o pqc_box

