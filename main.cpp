#include "ringct/bulletproofs.h"
#include <iostream>

using namespace rct;
using namespace std;

int main() {
    key k;
    for (int i = 0; i < 32; ++i) {
        k.bytes[i] = (unsigned char)i;
    }

    uint64_t v = 123456789;
    Bulletproof bp = bulletproof_PROVE(v, k);

    bool result = bulletproof_VERIFY(bp);
    cout << "result = " << result << endl;
}
