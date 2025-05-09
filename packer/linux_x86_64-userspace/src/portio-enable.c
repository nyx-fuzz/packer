#include <err.h>
#include <unistd.h>
#include <sys/io.h>
#include "nyx.h"

int main(int argc, char **argv) {
	if (ioperm(VMWARE_PORT, 4, 1))
		err(1, "ioperm");
	execvp(argv[1], argv+1);
	err(1, "execvp");
}
