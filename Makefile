all:
	gcc pcap-analysis.c -o pcap-analysis -lm

clean:
	rm -f *.o pcap-analysis