package main

import (
	"log"
	"firewall-go/internal"
	"firewall-go/api"
)

func main() {
	firewall := internal.NewFirewall()
	api.Init(firewall)

	// Lancer le serveur API REST dans une goroutine
	go api.StartAPI()

	// Appliquer les règles initiales depuis le fichier config
	// Par exemple, tu peux charger les règles depuis un fichier YAML comme décrit précédemment
	rules := loadInitialRules() // A implémenter selon ton propre besoin
	err := firewall.ApplyRules(rules)
	if err != nil {
		log.Fatalf("Error applying firewall rules: %v", err)
	}

	log.Println("Firewall rules applied successfully.")
}
