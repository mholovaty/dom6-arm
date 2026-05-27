/* loader_counters.h — per-symbol shim hit counters.
 *
 * Every nop_* thunk and every mac_* shim calls SHIM_HIT(SHIM__name).
 * Aggregate counts are dumped at clean exit or via SIGUSR2.  Useful for
 * spotting which Mac framework calls a particular code path actually
 * needs (especially when adding loader coverage for new game features). */
#ifndef LOADER_COUNTERS_H
#define LOADER_COUNTERS_H
#include <stdint.h>
#include <stdatomic.h>

#include "shim_enum.inc"

#define SHIM_HIT(id) atomic_fetch_add_explicit(&shim_counters[id], 1, memory_order_relaxed)

extern atomic_uint_fast64_t shim_counters[SHIM_COUNT];

void mac_shim_dump_counters(void);
void install_shim_dump_handler(void);

#endif /* LOADER_COUNTERS_H */
