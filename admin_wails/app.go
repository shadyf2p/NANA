package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// App struct
type App struct {
	ctx       context.Context
	serverCmd *exec.Cmd
	serverURL string
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{
		serverURL: "http://127.0.0.1:8787/",
	}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	_ = a.startPythonAdminServer()
}

func (a *App) shutdown(ctx context.Context) {
	_ = ctx
	if a.serverCmd != nil && a.serverCmd.Process != nil {
		_ = a.serverCmd.Process.Kill()
		a.serverCmd = nil
	}
}

func (a *App) GetServerURL() string {
	return a.serverURL
}

func (a *App) OpenInBrowser() bool {
	url := a.serverURL
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start() == nil
}

func (a *App) startPythonAdminServer() error {
	if a.serverCmd != nil {
		return nil
	}
	scriptPath := resolveServerScriptPath()
	if scriptPath == "" {
		return nil
	}

	cmd := exec.Command("py", "-3.13", scriptPath)
	cmd.Dir = filepath.Dir(scriptPath)
	cmd.Env = append(os.Environ(), "ADMIN_OPEN_BROWSER=0")
	if runtime.GOOS == "windows" {
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	}
	if err := cmd.Start(); err != nil {
		alt := exec.Command("python", scriptPath)
		alt.Dir = filepath.Dir(scriptPath)
		alt.Env = append(os.Environ(), "ADMIN_OPEN_BROWSER=0")
		if runtime.GOOS == "windows" {
			alt.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		}
		if err2 := alt.Start(); err2 != nil {
			return err
		}
		a.serverCmd = alt
	} else {
		a.serverCmd = cmd
	}

	// Give server a short warm-up window.
	time.Sleep(900 * time.Millisecond)
	return nil
}

func resolveServerScriptPath() string {
	if custom := os.Getenv("ADMIN_SERVER_SCRIPT"); custom != "" {
		if fileExists(custom) {
			return custom
		}
	}
	wd, _ := os.Getwd()
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	candidates := []string{
		filepath.Join(wd, "admin_portal", "server.py"),
		filepath.Join(exeDir, "admin_portal", "server.py"),
		filepath.Join(exeDir, "..", "admin_portal", "server.py"),
	}
	for _, c := range candidates {
		if fileExists(c) {
			return c
		}
	}
	return ""
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
