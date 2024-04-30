// Copyright 2024, Northwood Labs
//
// Licensed under the Apache License, Version 2.0 (the \"License\");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/lithammer/dedent"
	"github.com/northwood-labs/crowdstrike-falcon-downloader/crowdstrike"
)

func LongHelpText(text string) string {
	helpText := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("99")).
		Padding(1, 2) // lint:allow_raw_number

	return helpText.Render(
		strings.TrimSpace(
			dedent.Dedent(text),
		),
	)
}

func verifyEnvironment() {
	exit := false

	if os.Getenv("CROWDSTRIKE_CLIENT_ID") == "" {
		logger.Error("CROWDSTRIKE_CLIENT_ID is not set")
		exit = true
	}

	if os.Getenv("CROWDSTRIKE_CLIENT_SECRET") == "" {
		logger.Error("CROWDSTRIKE_CLIENT_SECRET is not set")
		exit = true
	}

	if exit {
		os.Exit(1)
	}
}

func filterData(data []crowdstrike.ListResources) []crowdstrike.ListResources {
	var filteredData []crowdstrike.ListResources

	for i := range data {
		d := data[i]

		if fAmzn1 && (fIntel64 || (!fIntel64 && !fArm64 && !fS390x)) {
			if strings.EqualFold(d.OS, "Amazon Linux") &&
				d.OSVersion == "1" && strings.Contains(d.Name, "x86_64") {
				filteredData = append(filteredData, d)
			}
		} else if fAmzn2 {
			if strings.EqualFold(d.OS, "Amazon Linux") && strings.HasPrefix(d.OSVersion, "2") && !strings.HasPrefix(d.OSVersion, "2023") {
				if fIntel64 && strings.Contains(d.Name, "x86_64") {
					filteredData = append(filteredData, d)
				} else if fArm64 && strings.Contains(d.Name, "aarch64") {
					filteredData = append(filteredData, d)
				} else if !fIntel64 && !fArm64 && !fS390x {
					filteredData = append(filteredData, d)
				}
			}
		} else if fAmzn2023 {
			if strings.EqualFold(d.OS, "Amazon Linux") && strings.HasPrefix(d.OSVersion, "2023") {
				if fIntel64 && strings.Contains(d.Name, "x86_64") {
					filteredData = append(filteredData, d)
				} else if fArm64 && strings.Contains(d.Name, "aarch64") {
					filteredData = append(filteredData, d)
				} else if !fIntel64 && !fArm64 && !fS390x {
					filteredData = append(filteredData, d)
				}
			}
		} else if fEL6 {
			if strings.HasPrefix(d.OS, "RHEL") && strings.HasPrefix(d.OSVersion, "6") {
				if fIntel64 && strings.Contains(d.Name, "x86_64") {
					filteredData = append(filteredData, d)
				} else if !fIntel64 && !fArm64 && !fS390x {
					filteredData = append(filteredData, d)
				}
			}
		} else if fEL7 {
			if strings.HasPrefix(d.OS, "RHEL") && strings.HasPrefix(d.OSVersion, "7") {
				if fIntel64 && strings.Contains(d.Name, "x86_64") {
					filteredData = append(filteredData, d)
				} else if fS390x && strings.Contains(d.Name, "s390x") {
					filteredData = append(filteredData, d)
				} else if !fIntel64 && !fArm64 && !fS390x {
					filteredData = append(filteredData, d)
				}
			}
		} else if fEL8 {
			if strings.HasPrefix(d.OS, "RHEL") && strings.HasPrefix(d.OSVersion, "8") {
				if fIntel64 && strings.Contains(d.Name, "x86_64") {
					filteredData = append(filteredData, d)
				} else if fArm64 && strings.Contains(d.Name, "aarch64") {
					filteredData = append(filteredData, d)
				} else if fS390x && strings.Contains(d.Name, "s390x") {
					filteredData = append(filteredData, d)
				} else if !fIntel64 && !fArm64 && !fS390x {
					filteredData = append(filteredData, d)
				}
			}
		} else if fEL9 {
			if strings.HasPrefix(d.OS, "RHEL") && strings.HasPrefix(d.OSVersion, "9") {
				if fIntel64 && strings.Contains(d.Name, "x86_64") {
					filteredData = append(filteredData, d)
				} else if fArm64 && strings.Contains(d.Name, "aarch64") {
					filteredData = append(filteredData, d)
				} else if fS390x && strings.Contains(d.Name, "s390x") {
					filteredData = append(filteredData, d)
				} else if !fIntel64 && !fArm64 && !fS390x {
					filteredData = append(filteredData, d)
				}
			}
		} else if fMac {
			if strings.HasPrefix(d.OS, "macOS") {
				if fIntel64 || fArm64 {
					filteredData = append(filteredData, d)
				} else if !fIntel64 && !fArm64 && !fS390x {
					filteredData = append(filteredData, d)
				}
			}
		} else if fSuse11 {
			if strings.HasPrefix(d.OS, "SLES") && strings.HasPrefix(d.OSVersion, "11") {
				if fIntel64 && strings.Contains(d.Name, "x86_64") {
					filteredData = append(filteredData, d)
				} else if !fIntel64 && !fArm64 && !fS390x {
					filteredData = append(filteredData, d)
				}
			}
		} else if fSuse12 {
			if strings.HasPrefix(d.OS, "SLES") && strings.HasPrefix(d.OSVersion, "12") {
				if fIntel64 && strings.Contains(d.Name, "x86_64") {
					filteredData = append(filteredData, d)
				} else if fS390x && strings.Contains(d.Name, "s390x") {
					filteredData = append(filteredData, d)
				} else if !fIntel64 && !fArm64 && !fS390x {
					filteredData = append(filteredData, d)
				}
			}
		} else if fSuse15 {
			if strings.HasPrefix(d.OS, "SLES") && strings.HasPrefix(d.OSVersion, "15") {
				if fIntel64 && strings.Contains(d.Name, "x86_64") {
					filteredData = append(filteredData, d)
				} else if fS390x && strings.Contains(d.Name, "s390x") {
					filteredData = append(filteredData, d)
				} else if !fIntel64 && !fArm64 && !fS390x {
					filteredData = append(filteredData, d)
				}
			}
		} else if fDebian {
			if strings.EqualFold(d.OS, "Debian") {
				if fIntel64 && strings.Contains(d.Name, "amd64") {
					filteredData = append(filteredData, d)
				} else if fArm64 && strings.Contains(d.Name, "arm64") {
					filteredData = append(filteredData, d)
				} else if !fIntel64 && !fArm64 && !fS390x {
					filteredData = append(filteredData, d)
				}
			}
		} else if fUbuntu {
			if strings.EqualFold(d.OS, "Ubuntu") {
				if fIntel64 && strings.Contains(d.Name, "amd64") {
					filteredData = append(filteredData, d)
				} else if fArm64 && strings.Contains(d.Name, "arm64") {
					filteredData = append(filteredData, d)
				} else if !fIntel64 && !fArm64 && !fS390x {
					filteredData = append(filteredData, d)
				}
			}
		} else if fWindows {
			if strings.EqualFold(d.OS, "Windows") {
				if fIntel64 {
					filteredData = append(filteredData, d)
				} else if !fIntel64 && !fArm64 && !fS390x {
					filteredData = append(filteredData, d)
				}
			}
		} else {
			filteredData = append(filteredData, d)
		}
	}

	return filteredData
}
