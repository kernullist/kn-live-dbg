#include "irp-binding-fixture.h"
volatile _ETHREAD ThreadFixture{};
volatile _IRP IrpFixture{};
volatile _IO_STACK_LOCATION StackFixture{};
int main() { return static_cast<int>(ThreadFixture.CreateTime + IrpFixture.Size + StackFixture.Control); }
