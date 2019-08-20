// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "tm.h"
#include "common/common-target.h"
#include "common/common-target-def.h"

// Set default optimization options.
static const struct default_options pu32_option_optimization_table[] = {
	// Enable redundant extension instructions removal at -O2 and higher.
	{ OPT_LEVELS_2_PLUS, OPT_free, NULL, 1 },
	// Enable function splitting at -O2 and higher.
	{ OPT_LEVELS_2_PLUS, OPT_freorder_blocks_and_partition, NULL, 1 },
	// The STC algorithm produces the smallest code.
	{ OPT_LEVELS_2_PLUS, OPT_freorder_blocks_algorithm_, NULL, REORDER_BLOCKS_ALGORITHM_STC },
	// Enable fgcse-sm at -O2 and higher.
	{ OPT_LEVELS_2_PLUS, OPT_fgcse_sm, NULL, 1 },
	// Enable fgcse-las at -O2 and higher.
	{ OPT_LEVELS_2_PLUS, OPT_fgcse_las, NULL, 1 },
	// Enable fgcse-after-reload at -O2 and higher.
	{ OPT_LEVELS_2_PLUS, OPT_fgcse_after_reload, NULL, 1 },
	// Disable fcaller-saves by default.
	{ OPT_LEVELS_ALL, OPT_fcaller_saves, NULL, 0 },
	{ OPT_LEVELS_NONE, 0, NULL, 0 }
};

#undef  TARGET_DEFAULT_TARGET_FLAGS
#define TARGET_DEFAULT_TARGET_FLAGS TARGET_DEFAULT

#undef  TARGET_OPTION_OPTIMIZATION_TABLE
#define TARGET_OPTION_OPTIMIZATION_TABLE pu32_option_optimization_table

struct gcc_targetm_common targetm_common = TARGETM_COMMON_INITIALIZER;
