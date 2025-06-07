package logging

const (
	LevelDebug string = "DEBUG"
	LevelInfo  string = "INFO"
	LevelWarn  string = "WARN"
	LevelError string = "ERROR"
)

var LogLevels = map[string]int{
	LevelError: 1,
	LevelWarn:  2,
	LevelInfo:  3,
	LevelDebug: 4,
}
