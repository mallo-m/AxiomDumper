#pragma once
#ifndef SYSCALL_H
# define SYSCALL_H

# include "Typedefs.h"

extern "C" void AxiomSetJump(void* jumpAddress);
extern "C" void AxiomCallSetup(int systemServiceNumber);
extern "C" void* AxiomCall(...);
#define IndirectSyscall(status, func, ...) \
    AxiomSetJump(AXIOM_GetSyscallAddrByHash(func)); \
    AxiomCallSetup(AXIOM_GetSNNByHash(func)); \
    status = (NTSTATUS)AxiomCall(__VA_ARGS__);

#endif
