// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include "eraise.h"

#if 1
#define TRACE
#endif

void __eraise(const char* file, uint32_t line, const char* func, int errnum)
{
#ifdef TRACE
    fprintf(stderr, "%s(%u): %s(): %d\n", file, line, func, errnum);
#endif
}
