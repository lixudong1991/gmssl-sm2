cc = gcc
prom = libsm2.so
deps = $(shell find ./ -name "*.h")
src = $(shell find ./ -name "*.c")
obj = $(src:%.c=%.o)
INC = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux
$(prom): $(obj)
	$(cc) -shared -o $(prom) $(obj) -L/home/lxd/project/GmSSL-master -lcrypto 
%.o: %.c $(deps) 
	$(cc) -fPIC -g $(INC) -c $< -o $@ 
clean:
	rm -rf $(obj) $(prom)
