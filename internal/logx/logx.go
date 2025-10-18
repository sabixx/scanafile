package logx

import (
	"fmt"
	"os"
	"time"
)

var DebugEnabled bool

func ts() string { return time.Now().UTC().Format("2006-01-02T15:04:05Z") }

func Info(f string, a ...any)  { fmt.Printf("[%s] [INFO]  %s\n", ts(), fmt.Sprintf(f, a...)) }
func Warn(f string, a ...any)  { fmt.Fprintf(os.Stderr, "[%s] [WARN]  %s\n", ts(), fmt.Sprintf(f, a...)) }
func Error(f string, a ...any) { fmt.Fprintf(os.Stderr, "[%s] [ERROR] %s\n", ts(), fmt.Sprintf(f, a...)) }
func Debug(f string, a ...any) { if DebugEnabled { fmt.Printf("[%s] [DEBUG] %s\n", ts(), fmt.Sprintf(f, a...)) } }
