package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"firewall-go/internal"
)

var firewall *internal.Firewall

func Init(fw *internal.Firewall) {
	firewall = fw
}

func ApplyRulesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var rules []internal.Rule
	err := json.NewDecoder(r.Body).Decode(&rules)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error decoding rules: %v", err), http.StatusBadRequest)
		return
	}

	err = firewall.ApplyRules(rules)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error applying rules: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Rules applied successfully"))
}

func GetStatusHandler(w http.ResponseWriter, r *http.Request) {
	status := "Firewall is active and running."
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(status))
}

func StartAPI() {
	http.HandleFunc("/apply-rules", ApplyRulesHandler)
	http.HandleFunc("/status", GetStatusHandler)

	port := ":8080"
	log.Printf("Starting API server on %s", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
