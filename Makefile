all : 1m_detect

1m_detect: main.o
	g++ -g -o 1m_detect main.o -lnetfilter_queue

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f 1m_detect
	rm -f *.o

