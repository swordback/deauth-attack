LDLIBS=-lpcap

all: deauth-attack

mac.o : mac.h mac.cpp

main.o : mac.h main.cpp

deauth-attack: mac.o main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f deauth-attack *.o