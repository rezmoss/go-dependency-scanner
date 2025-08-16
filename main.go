package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Module struct {
	Path     string
	Version  string
	Indirect bool
}

type GoMod struct {
	Module   Module
	Requires []Module
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "deps":
		analyzeDependencies()
	case "vulns":
		checkVulnerabilities()
	case "licenses":
		checkLicenses()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Go Dependency Analyzer (Pure Go)")
	fmt.Println("Usage: go run main.go <command>")
	fmt.Println("\nCommands:")
	fmt.Println("  deps      List all dependencies")
	fmt.Println("  vulns     Check for vulnerabilities")
	fmt.Println("  licenses  Check license compliance")
}

func parseGoMod() (*GoMod, error) {
	file, err := os.Open("go.mod")
	if err != nil {
		return nil, fmt.Errorf("go.mod not found: %v", err)
	}
	defer file.Close()

	goMod := &GoMod{
		Requires: []Module{},
	}

	scanner := bufio.NewScanner(file)
	inRequire := false
	requireRegex := regexp.MustCompile(`^\s*([^\s]+)\s+([^\s]+)(?:\s+//\s*indirect)?`)
	moduleRegex := regexp.MustCompile(`^module\s+(.+)`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "module ") {
			if matches := moduleRegex.FindStringSubmatch(line); len(matches) > 1 {
				goMod.Module = Module{Path: matches[1]}
			}
		}

		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}

		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		if inRequire || strings.HasPrefix(line, "require ") {
			cleanLine := strings.TrimPrefix(line, "require ")
			if matches := requireRegex.FindStringSubmatch(cleanLine); len(matches) >= 3 {
				module := Module{
					Path:     matches[1],
					Version:  matches[2],
					Indirect: strings.Contains(line, "indirect"),
				}
				goMod.Requires = append(goMod.Requires, module)
			}
		}
	}

	return goMod, scanner.Err()
}

func parseGoSum() map[string]string {
	checksums := make(map[string]string)

	file, err := os.Open("go.sum")
	if err != nil {
		return checksums
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) >= 3 {
			module := parts[0] + "@" + parts[1]
			checksums[module] = parts[2]
		}
	}

	return checksums
}

func fetchVulnerabilitiesForModule(modulePath, version string) []string {
	vulns := checkGoVulnDB(modulePath)
	if len(vulns) > 0 {
		return vulns
	}

	return checkOSVDatabase(modulePath, version)
}

func checkGoVulnDB(modulePath string) []string {
	// Go vulnerability database endpoint
	url := fmt.Sprintf("https://pkg.go.dev/vuln/%s", modulePath)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return []string{}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []string{}
	}

	content := string(body)
	if strings.Contains(content, "Vulnerability") || strings.Contains(content, "CVE-") {
		return []string{"Vulnerability detected - check https://pkg.go.dev/vuln/" + modulePath}
	}

	return []string{}
}

func checkOSVDatabase(modulePath, version string) []string {
	url := "https://api.osv.dev/v1/query"

	payload := map[string]interface{}{
		"package": map[string]string{
			"name":      modulePath,
			"ecosystem": "Go",
		},
		"version": version,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return []string{}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return []string{}
	}

	var result struct {
		Vulns []struct {
			ID      string `json:"id"`
			Summary string `json:"summary"`
		} `json:"vulns"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return []string{}
	}

	var vulnerabilities []string
	for _, vuln := range result.Vulns {
		vulnStr := fmt.Sprintf("%s: %s", vuln.ID, vuln.Summary)
		vulnerabilities = append(vulnerabilities, vulnStr)
	}

	return vulnerabilities
}

func analyzeDependencies() {
	fmt.Println("📦 Analyzing Dependencies...")

	goMod, err := parseGoMod()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	checksums := parseGoSum()

	fmt.Printf("\n✅ Module: %s\n", goMod.Module.Path)
	fmt.Printf("Found %d dependencies:\n\n", len(goMod.Requires))

	direct, indirect := 0, 0

	sort.Slice(goMod.Requires, func(i, j int) bool {
		return goMod.Requires[i].Path < goMod.Requires[j].Path
	})

	for _, mod := range goMod.Requires {
		status := "direct  "
		if mod.Indirect {
			status = "indirect"
			indirect++
		} else {
			direct++
		}

		checksumKey := mod.Path + "@" + mod.Version
		hasChecksum := "❌"
		if _, exists := checksums[checksumKey]; exists {
			hasChecksum = "✅"
		}

		fmt.Printf("  %s %s@%-12s (%s)\n", hasChecksum, mod.Path, mod.Version, status)
	}

	fmt.Printf("\nSummary: %d direct, %d indirect dependencies\n", direct, indirect)
	fmt.Printf("Checksums verified: %d/%d\n", len(checksums)/2, len(goMod.Requires))
}

func checkVulnerabilities() {
	fmt.Println("🔍 Checking for Vulnerabilities...")

	goMod, err := parseGoMod()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	vulnerableModules := 0
	totalVulns := 0

	fmt.Println("\n🔍 Vulnerability Scan Results:")

	for i, mod := range goMod.Requires {
		fmt.Printf("\r🔍 Scanning %d/%d: %s", i+1, len(goMod.Requires), mod.Path)
		vulns := fetchVulnerabilitiesForModule(mod.Path, mod.Version)
		if len(vulns) > 0 {
			vulnerableModules++
			fmt.Printf("\n🚨 %s@%s:\n", mod.Path, mod.Version)
			for _, vuln := range vulns {
				fmt.Printf("  - %s\n", vuln)
				totalVulns++
			}
		} else {
			fmt.Printf("\r✅ Scanned %d/%d: %s - Clean\n", i+1, len(goMod.Requires), mod.Path)
		}
	}

	if vulnerableModules == 0 {
		fmt.Println("✅ No known vulnerabilities found in current dependencies!")
	} else {
		fmt.Printf("\n⚠️  Summary: %d vulnerable modules, %d total vulnerabilities\n", vulnerableModules, totalVulns)
		fmt.Println("🔧 Recommendation: Update vulnerable dependencies to latest versions")
	}

}

func checkLicenses() {
	fmt.Println("📜 Checking License Compliance...")

	goMod, err := parseGoMod()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	licenseCount := make(map[string]int)

	fmt.Println("\n📋 License Analysis:")
	fmt.Println("Fetching license information from repositories...")

	for i, mod := range goMod.Requires {
		fmt.Printf("\rProcessing %d/%d...", i+1, len(goMod.Requires))

		license := fetchLicenseFromRepo(mod.Path)
		licenseCount[license]++

		emoji := getLicenseEmoji(license)
		fmt.Printf("\r  %s %s: %s\n", emoji, mod.Path, license)
	}

	fmt.Println("\n📊 License Distribution:")

	type licenseStat struct {
		name  string
		count int
	}

	var stats []licenseStat
	for license, count := range licenseCount {
		stats = append(stats, licenseStat{license, count})
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].count > stats[j].count
	})

	for _, stat := range stats {
		percentage := float64(stat.count) / float64(len(goMod.Requires)) * 100
		fmt.Printf("  %s: %d modules (%.1f%%)\n", stat.name, stat.count, percentage)
	}

	if unknown := licenseCount["Unknown"]; unknown > 0 {
		fmt.Printf("\n⚠️  %d modules have unknown licenses - manual review required\n", unknown)
	}

	if copyleft := licenseCount["GPL-3.0"] + licenseCount["LGPL-2.1"]; copyleft > 0 {
		fmt.Printf("⚠️  %d modules use copyleft licenses - check compatibility\n", copyleft)
	}
}

func fetchLicenseFromRepo(modulePath string) string {
	if strings.HasPrefix(modulePath, "golang.org/x/") {
		return "BSD-3-Clause"
	}

	if !strings.HasPrefix(modulePath, "github.com/") {
		return "Unknown"
	}

	parts := strings.Split(modulePath, "/")
	if len(parts) < 3 {
		return "Unknown"
	}

	owner := parts[1]
	repo := parts[2]

	return fetchGitHubLicense(owner, repo)

}

func fetchGitHubLicense(owner, repo string) string {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/license", owner, repo)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "Unknown"
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "Unknown"
	}

	var result struct {
		License struct {
			SPDXID string `json:"spdx_id"`
			Name   string `json:"name"`
		} `json:"license"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "Unknown"
	}

	if result.License.SPDXID != "" && result.License.SPDXID != "NOASSERTION" {
		return result.License.SPDXID
	}

	return "Unknown"
}

func getLicenseEmoji(license string) string {
	switch license {
	case "MIT", "BSD-3-Clause", "Apache-2.0":
		return "✅"
	case "GPL-3.0", "LGPL-2.1":
		return "⚠️"
	case "Unknown":
		return "❓"
	default:
		return "📄"
	}
}
