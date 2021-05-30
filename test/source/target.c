#include <stdio.h>

int min(int a, int b) {
	int c = 1;
	if (c > 1) {
		printf("hello there");
		c = 2;
	}
	return a <= b ? a : b;
}

int main() {
	int a = min(2,3);
	printf("%d\n", a);
}
