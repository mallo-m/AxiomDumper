#include "AxiomDumper.h"
#include "Typedefs.h"
#include <windows.h>

void InitializeObjectAttributes(
    POBJECT_ATTRIBUTES p,
    PUNICODE_STRING n,
    ULONG a,
    HANDLE r,
    PVOID s
) {
    p->Length = sizeof(OBJECT_ATTRIBUTES);
    p->RootDirectory = r;
    p->Attributes = a;
    p->ObjectName = n;
    p->SecurityDescriptor = s;
    p->SecurityQualityOfService = nullptr;
}
