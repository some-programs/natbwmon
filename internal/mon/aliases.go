package mon

// TODO: global state
var AliasesMap map[string]string

func init() {
	AliasesMap = make(map[string]string, 0)
}
