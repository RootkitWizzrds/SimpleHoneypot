package api

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/sys/unix"
)

func getTerminalWidth() int {
	fd := int(unix.Stdin)
	width, _, err := terminal.GetSize(fd)
	if err != nil {
		return 80
	}
	return width
}

func LogRequest(r *http.Request) {
	termWidth := getTerminalWidth()
	border := strings.Repeat("=", termWidth)

	log.Printf("\n=== Request Logged ===")
	log.Printf("Time: %s", time.Now().Format(time.RFC3339))
	log.Printf("Accessed %s from %s", r.URL.Path, r.RemoteAddr)
	log.Printf("User-Agent: %s", r.UserAgent())
	log.Printf("Referrer: %s", r.Referer())
	log.Printf("Request Method: %s", r.Method)
	log.Printf("Request Headers: %v", r.Header)

	if jsEnabled := r.URL.Query().Get("js"); jsEnabled != "" {
		log.Printf("JavaScript Enabled: %s", jsEnabled)
	} else {
		log.Printf("JavaScript Enabled: Not Reported")
	}

	if r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading request body: %v", err)
		} else {
			log.Printf("Request Body: %s", string(body))
			r.Body = io.NopCloser(strings.NewReader(string(body)))
		}
	}

	fmt.Println(border)
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	LogRequest(r)
	fmt.Fprintln(w, "Welcome to the honeypot!")
}

func VulnerableHandler(w http.ResponseWriter, r *http.Request) {
	LogRequest(r)
	fmt.Fprintln(w, "This is a simulated vulnerable endpoint.")
}

func SQLInjectionHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")
	LogRequest(r)

	if strings.Contains(query, "DROP") || strings.Contains(query, "DELETE") {
		log.Printf("Dangerous SQL detected: %s", query)
	}

	fmt.Fprintln(w, "SQL Injection handler response.")
}

func CommandInjectionHandler(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")
	LogRequest(r)

	if strings.Contains(command, "rm") || strings.Contains(command, "shutdown") {
		log.Printf("Dangerous command detected: %s", command)
	}

	fmt.Fprintln(w, "Command Injection handler response.")
}

func FileUploadHandler(w http.ResponseWriter, r *http.Request) {
	LogRequest(r)

	if r.Method == http.MethodPost {
		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "Error uploading file", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		dst, err := os.Create(filepath.Join("uploads", "uploaded_file"))
		if err != nil {
			http.Error(w, "Error saving file", http.StatusInternalServerError)
			return
		}
		defer dst.Close()

		if _, err := io.Copy(dst, file); err != nil {
			http.Error(w, "Error saving file", http.StatusInternalServerError)
			return
		}

		log.Printf("File uploaded from %s", r.RemoteAddr)
		fmt.Fprintln(w, "File uploaded successfully.")
	} else {
		http.ServeFile(w, r, "web/static/upload.html")
	}
}

func AdminLoginHandler(w http.ResponseWriter, r *http.Request) {
	LogRequest(r)

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		log.Printf("Admin login attempt: %s:%s", username, password)

		if username == "admin" && password == "admin" {
			http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
			return
		}
	}
	http.ServeFile(w, r, "web/admin/login.html")
}

func AdminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	LogRequest(r)
	http.ServeFile(w, r, "web/admin/dashboard.html")
}

func PhpMyAdminLoginHandler(w http.ResponseWriter, r *http.Request) {
	LogRequest(r)

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		log.Printf("phpMyAdmin login attempt: %s:%s", username, password)

		if username == "admin" && password == "admin" {
			http.Redirect(w, r, "/phpmyadmin/dashboard", http.StatusSeeOther)
			return
		}
	}
	http.ServeFile(w, r, "web/phpmyadmin/login.html")
}

func PhpMyAdminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	LogRequest(r)
	http.ServeFile(w, r, "web/phpmyadmin/index.html")
}

func JsEnabledHandler(w http.ResponseWriter, r *http.Request) {
	LogRequest(r)
	log.Println("JavaScript is enabled")
	w.WriteHeader(http.StatusNoContent)
}

func ServeFileHandler(filePath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		LogRequest(r)
		log.Printf("Serving file: %s", filePath)
		http.ServeFile(w, r, filePath)
	}
}

func RateLimitHandler(next http.Handler) http.Handler {
	ipRequests := make(map[string]int)
	const rateLimit = 100
	const rateLimitPeriod = time.Minute

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		ipRequests[ip]++
		if ipRequests[ip] > rateLimit {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		time.AfterFunc(rateLimitPeriod, func() {
			ipRequests[ip]--
		})
		next.ServeHTTP(w, r)
	})
}

func BlacklistHandler(next http.Handler) http.Handler {
	blockedIPs := map[string]bool{
		"192.168.1.1": true,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if blockedIPs[r.RemoteAddr] {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
