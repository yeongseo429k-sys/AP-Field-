LDLIBS   = -lpcap
CXXFLAGS = -Wall -O2

all: deauth-attack

deauth-attack: deauth-attack.o
	$(CXX) -o $@ $^ $(LDLIBS)

clean:
	rm -f deauth-attack *.o