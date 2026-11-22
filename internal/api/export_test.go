package api

// Test hooks: they lower a limit and return the old value.

func SetMaxExportItems(n int) int   { old := maxExportItems; maxExportItems = n; return old }
func SetActivityChunk(n int) int    { old := activityChunk; activityChunk = n; return old }
func SetWalkBudget(n int) int       { old := walkBudget; walkBudget = n; return old }
func SetAuditBudget(n int) int      { old := auditBudget; auditBudget = n; return old }
func SetExportWorkBudget(n int) int { old := exportWorkBudget; exportWorkBudget = n; return old }
