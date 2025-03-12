package logging

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Logger struct {
	MinLevel string
}

func CreateLogger(minLevel string) *Logger {
	return &Logger{
		MinLevel: minLevel,
	}
}

func shouldLog(minLevel, level string) bool {
	return LogLevels[strings.ToUpper(minLevel)] >= LogLevels[strings.ToUpper(level)]
}

func (logger *Logger) Log(level string, format string, a ...interface{}) {
	if !shouldLog(logger.MinLevel, level) {
		return
	}

	currentTime := time.Now().Format("2006-01-02 15:04:05")
	os.Stdout.WriteString(currentTime + " [" + level + "]" + " [traefik-oidc-auth] " + fmt.Sprintf(format, a...) + "\n")
}
