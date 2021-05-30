#include <stdio.h>

int min(int a, int b) {
	return a <= b ? a : b;
}

int main() {
	int a = min(2,3);
	printf("%d\n", a);
}
