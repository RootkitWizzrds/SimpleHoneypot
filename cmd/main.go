package main

import (
	"fmt"
	"honeypot/api" // Import the correct package for handlers
	"log"
	"net/http"
	"runtime"
)

func clearScreen() {
	switch runtime.GOOS {
	case "windows":
		// For Windows
		fmt.Print("\033[H\033[2J")
	case "linux", "darwin":
		// For Linux and macOS
		fmt.Print("\033[H\033[2J")
	default:
		log.Println("Unsupported OS")
	}
}

func main() {
	clearScreen()
	mux := http.NewServeMux()

	// Register handlers
	mux.HandleFunc("/", api.IndexHandler)
	mux.HandleFunc("/vulnerable", api.VulnerableHandler)
	mux.HandleFunc("/sql", api.SQLInjectionHandler)
	mux.HandleFunc("/command", api.CommandInjectionHandler)
	mux.HandleFunc("/upload", api.FileUploadHandler)
	mux.HandleFunc("/admin/login", api.AdminLoginHandler)
	mux.HandleFunc("/admin/dashboard", api.AdminDashboardHandler)
	mux.HandleFunc("/phpmyadmin/login", api.PhpMyAdminLoginHandler)
	mux.HandleFunc("/phpmyadmin/dashboard", api.PhpMyAdminDashboardHandler)
	mux.HandleFunc("/js-enabled", api.JsEnabledHandler) // Add JS enabled handler

	// Serve .sql files with logging
	mux.HandleFunc("/database.sql", api.ServeFileHandler("web/database.sql"))
	mux.HandleFunc("/dump.sql", api.ServeFileHandler("web/dump.sql"))

	handler := api.BlacklistHandler(api.RateLimitHandler(mux))

	address := ":8080"
	log.Printf("Starting server on %s", address)

	printEndpoints(address)

	if err := http.ListenAndServe(address, handler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func printEndpoints(address string) {
	baseURL := "http://localhost" + address

	endpoints := []struct {
		Path        string
		Description string
	}{
		{"/", "Welcome page"},
		{"/vulnerable", "Simulated vulnerable endpoint"},
		{"/sql", "Simulated SQL Injection vulnerability"},
		{"/command", "Simulated Command Injection vulnerability"},
		{"/upload", "Simulated File Upload vulnerability"},
		{"/admin/login", "Fake Admin Panel Login"},
		{"/admin/dashboard", "Fake Admin Panel Dashboard"},
		{"/phpmyadmin/login", "Fake phpMyAdmin Login"},
		{"/phpmyadmin/dashboard", "Fake phpMyAdmin Dashboard"},
		{"/database.sql", "Simulated database schema file"},
		{"/dump.sql", "Simulated database dump file"},
		{"/js-enabled", "JavaScript detection endpoint"},
	}

	log.Println("\n\n\nAvailable Endpoints:\n")

	for _, endpoint := range endpoints {
		log.Printf(
			"Path: %-30s - %-45s - URL: %s%s\n",
			endpoint.Path,
			endpoint.Description,
			baseURL,
			endpoint.Path,
		)
	}

	log.Println("\n\n")
}
