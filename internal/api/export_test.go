package api

// SetMaxExportItems lowers the cap of one JSONL export; it returns the old one.
func SetMaxExportItems(n int) int {
	old := maxExportItems
	maxExportItems = n
	return old
}
