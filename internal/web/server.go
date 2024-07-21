package api

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request at %s from %s", r.URL.Path, r.RemoteAddr)
	fmt.Fprintln(w, "Welcome to the honeypot!")
}

func VulnerableHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Vulnerable endpoint accessed: %s from %s", r.URL.Path, r.RemoteAddr)
	fmt.Fprintln(w, "This is a simulated vulnerable endpoint.")
}

func SQLInjectionHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")
	log.Printf("SQL Injection attempt: %s from %s", query, r.RemoteAddr)

	if strings.Contains(query, "DROP") || strings.Contains(query, "DELETE") {
		log.Printf("Dangerous SQL detected: %s", query)
	}

	fmt.Fprintln(w, "SQL Injection handler response.")
}

func CommandInjectionHandler(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")
	log.Printf("Command Injection attempt: %s from %s", command, r.RemoteAddr)

	if strings.Contains(command, "rm") || strings.Contains(command, "shutdown") {
		log.Printf("Dangerous command detected: %s", command)
	}

	fmt.Fprintln(w, "Command Injection handler response.")
}

func FileUploadHandler(w http.ResponseWriter, r *http.Request) {
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
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		log.Printf("Admin login attempt: %s:%s from %s", username, password, r.RemoteAddr)

		if username == "admin" && password == "admin" {
			http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
			return
		}
	}
	http.ServeFile(w, r, "web/admin/login.html")
}

func AdminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "web/admin/dashboard.html")
}

func PhpMyAdminLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		log.Printf("phpMyAdmin login attempt: %s:%s from %s", username, password, r.RemoteAddr)

		if username == "admin" && password == "admin" {
			http.Redirect(w, r, "/phpmyadmin/dashboard", http.StatusSeeOther)
			return
		}
	}
	http.ServeFile(w, r, "web/phpmyadmin/login.html")
}

func PhpMyAdminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "web/phpmyadmin/index.html")
}
