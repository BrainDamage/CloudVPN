
#ifndef CVPN_TIMESTAMP_H
#define CVPN_TIMESTAMP_H

#include <stdint.h>

//timestamp is microseconds since epoch. *Accurate* *enough* to compute both
//bandwidths, hires delays, and dates even in long-term processes.
//NOTE that 64bit integer can measure percise time until 07:36:10 UTC on the
//28th of May year 60425 after Christ's birth. might turn into a fixme later.

uint64_t timestamp();
void timestamp_update();

#endif

