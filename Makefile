main:
	chmod 644 crypto.c
	gcc crypto.c -shared -fPIC -I /usr/local/include/pbc -L /usr/local/include/pbc/ -Wl,-rpath /usr/local/include/pbc/ -l pbc -l gmp -o crypto.so
