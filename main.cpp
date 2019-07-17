#include "ringct/bulletproofs.h"
#include <iostream>
#include <random>
#include <time.h>

using namespace rct;
using namespace std;

int main() {
    srand (time(nullptr));
    key k;
    for (int i = 0; i < 31; ++i) {
        k.bytes[i] = (unsigned char)(rand() % 255);
    }

    uint64_t v = 1234567890000;
    Bulletproof bp = bulletproof_PROVE(v, k);

    bool result = bulletproof_VERIFY(bp);
    cout << "result = " << result << endl;
}
