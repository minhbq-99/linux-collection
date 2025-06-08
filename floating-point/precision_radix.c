/*
 * Implement the precision and radix detection algorithm for floating point
 * number based on this paper:
 *
 * Michael A. Malcolm. 1972. Algorithms to reveal properties of floating-point
 * arithmetic. Commun. ACM 15, 11 (Nov. 1972), 949–951.
 * https://doi.org/10.1145/355606.361870
 */


#include <stdio.h>
#include <string.h>

#define	DEFINE_DETECTION(type) \
	int detect_precision_##type(void) 	\
	{					\
		int precision = 0;		\
		type a = 1.0;			\
		type b = a + 1.0;		\
						\
		while (b - a == 1.0) {		\
			a = a * 2;		\
			precision++;		\
			b = a + 1.0;		\
		}				\
						\
		return precision;		\
	}					\
						\
	int detect_radix_##type(int precision)		\
	{						\
		type a = (type)(1ULL << precision);	\
		int radix = 1;				\
		type b = radix * 1.0;			\
		type c = a + b;				\
							\
		while (c - a != b) {			\
			radix++;			\
			b = radix * 1.0;		\
			c = a + b;			\
		}					\
							\
		return radix;				\
	}

DEFINE_DETECTION(float);
DEFINE_DETECTION(double);

void print_usage(const char *prog)
{
	printf("Usage: %s (float|double)\n", prog);
}

int main(int argc, char **argv)
{
	int (*detect_precision_fn)(void);
	int (*detect_radix_fn)(int);
	int precision;

	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

	if (!strcmp(argv[1], "float")) {
		detect_precision_fn = detect_precision_float;
		detect_radix_fn = detect_radix_float;
	} else if (!strcmp(argv[1], "double")) {
		detect_precision_fn = detect_precision_double;
		detect_radix_fn = detect_radix_double;
	} else {
		print_usage(argv[0]);
		return 1;
	}

	precision = detect_precision_fn();
	printf("Precision: %u, radix: %u\n", precision, detect_radix_fn(precision));
	return 0;
}

