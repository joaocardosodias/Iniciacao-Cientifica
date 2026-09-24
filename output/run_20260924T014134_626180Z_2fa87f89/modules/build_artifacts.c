#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>

/*
 * No repository files or release-pipeline specifications were provided for
 * inspection. In particular, the required artifacts, their formats, inputs,
 * and the expected build_artifacts signature are unknown.
 *
 * This generic entry point deliberately produces no artifacts. Returning
 * ENOTSUP makes the missing specification explicit rather than inventing
 * domain behavior.
 */
static int build_artifacts(void)
{
    const char *message =
        "build_artifacts: artifact requirements and parameters are unspecified";

    if (fprintf(stderr, "%s\n", message) < 0)
        return EIO;

    return ENOTSUP;
}

int main(void)
{
    int result = build_artifacts();

    if (result != 0) {
        if (result != ENOTSUP)
            fprintf(stderr, "build_artifacts: %s\n", strerror(result));
        return 1;
    }

    return 0;
}