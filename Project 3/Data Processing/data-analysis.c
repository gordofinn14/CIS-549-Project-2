
#include <stdio.h>
#include <stdlib.h>

void extract_data(char* in_filename)
{
    FILE* in;
    FILE* out;
    char buffer[256];
    double time = 0.0;
    double throughput = 0.0;
    double max = 0.0;
    double total = 0.0;
    double count = 0.0;
    double average = 0.0;    

    in = fopen(in_filename, "r");

    if (in == NULL) {
        perror("Error reading file");
        exit(1);
    }

    while (fgets(buffer, sizeof(buffer), in) != NULL) {
        sscanf(buffer, "%lf %lf", &time, &throughput);
        if (throughput > 0) {
            total = total + throughput;
            count = count + 1;
            if (throughput > max) {
                max = throughput;
            }
        }
    }

    fclose(in);

    out = fopen("output.txt", "a");
    if (out == NULL) {
        perror("Error writing to file");
        exit(1);
    }

    average = total / count;

    fprintf(out, "%s\t%f\t%f\n", in_filename, max, average);

    fclose(out);
} /*end func */

int main(int argc, char* argv[])
{
    if (argc < 2) {
        perror("Need to specify a file name");
        exit(1);
    }

    extract_data(argv[1]);

    exit(0);
} /*end prog */
