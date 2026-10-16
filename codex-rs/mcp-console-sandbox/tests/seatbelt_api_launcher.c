// Investigation only: compare policy application without changing target
// topology.
#include <dlfcn.h>
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int sandbox_init_with_parameters(const char *, uint64_t,
                                        const char *const[], char **);
extern void sandbox_free_error(char *);

static void *symbol(void *library, const char *name) {
    void *value = dlsym(library, name);
    if (value == NULL) {
        errx(1, "%s: %s", name, dlerror());
    }
    return value;
}

int main(int argc, char **argv) {
    if (argc < 4 ||
        (strcmp(argv[1], "init") != 0 && strcmp(argv[1], "compiled") != 0)) {
        errx(1, "expected init|compiled profile command [args...]");
    }
    FILE *file = fopen(argv[2], "rb");
    if (file == NULL || fseek(file, 0, SEEK_END) != 0) {
        err(1, "open profile");
    }
    long length = ftell(file);
    if (length <= 0 || fseek(file, 0, SEEK_SET) != 0) {
        errx(1, "invalid profile size");
    }
    char *policy = malloc((size_t)length + 1);
    if (policy == NULL) {
        err(1, "allocate profile");
    }
    if (fread(policy, 1, (size_t)length, file) != (size_t)length ||
        memchr(policy, '\0', (size_t)length) != NULL || fclose(file) != 0) {
        errx(1, "read complete profile");
    }
    policy[length] = '\0';
    fprintf(stderr, "SEATBELT_API mode=%s pid=%d profile=%s bytes=%ld\n",
            argv[1], getpid(), argv[2], length);
    char *error = NULL;
    int status;
    if (strcmp(argv[1], "init") == 0) {
        // Match the native helper's non-null, empty parameter array and flags.
        const char *parameters[] = {NULL};
        status = sandbox_init_with_parameters(policy, 0, parameters, &error);
    } else {
        // The initialization wrapper also loads this library and calls these
        // functions. Keep its handle alive until exec, as the system launcher
        // does.
        void *library = dlopen("/usr/lib/libsandbox.1.dylib",
                               RTLD_LAZY | RTLD_LOCAL | RTLD_FIRST);
        if (library == NULL) {
            errx(1, "load policy compiler: %s", dlerror());
        }
        void *(*create_params)(void) = symbol(library, "sandbox_create_params");
        void *(*compile_string)(const char *, void *, char **) =
            symbol(library, "sandbox_compile_string");
        int (*apply)(void *) = symbol(library, "sandbox_apply");
        void (*free_profile)(void *) = symbol(library, "sandbox_free_profile");
        void (*free_params)(void *) = symbol(library, "sandbox_free_params");
        void *parameters = create_params();
        if (parameters == NULL) {
            err(1, "create policy parameters");
        }
        void *profile = compile_string(policy, parameters, &error);
        if (profile == NULL) {
            errx(1, "compile policy: %s",
                 error == NULL ? "no diagnostic" : error);
        }
        status = apply(profile);
        free_profile(profile);
        free_params(parameters);
    }
    if (status != 0) {
        if (error != NULL) {
            fprintf(stderr, "apply policy: %s\n", error);
            sandbox_free_error(error);
            return 1;
        }
        err(1, "apply policy");
    }
    free(policy);
    execv(argv[3], &argv[3]);
    err(1, "exec target");
}
