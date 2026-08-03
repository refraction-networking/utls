package tls

type disabledGoDebugValue struct{}

func (disabledGoDebugValue) Value() string { return "" }

func (disabledGoDebugValue) IncNonDefault() {}

var tlssha1 disabledGoDebugValue
