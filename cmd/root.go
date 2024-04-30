// Copyright 2024, Northwood Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
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
	"cmp"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh/spinner"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	"github.com/dustin/go-humanize"
	"github.com/northwood-labs/crowdstrike-falcon-downloader/crowdstrike"
	"github.com/spf13/cobra"
)

const height = 20

var (
	fDownload bool
	fLatest   bool
	fJson     bool
	fVerbose  bool

	fAmzn1    bool
	fAmzn2    bool
	fAmzn2023 bool
	fEL6      bool
	fEL7      bool
	fEL8      bool
	fEL9      bool
	fMac      bool
	fSuse11   bool
	fSuse12   bool
	fSuse15   bool
	fDebian   bool
	fUbuntu   bool
	fWindows  bool
	fArm64    bool
	fIntel64  bool
	fS390x    bool

	hasOSFlag  bool
	hasCPUFlag bool

	apiToken  string
	sensor    crowdstrike.ListResources
	sensors   []crowdstrike.ListResources
	sensorMap = map[string]crowdstrike.ListResources{}

	baseStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240"))

	keys = keyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "move up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "move down"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "toggle help"),
		),
		Enter: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "make selection"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "esc", "ctrl+c"),
			key.WithHelp("q/esc", "quit"),
		),
	}

	logger = log.NewWithOptions(os.Stderr, log.Options{
		ReportTimestamp: true,
		TimeFormat:      time.Kitchen,
		Prefix:          "crowdstrike-falcon-downloader",
	})

	// rootCmd represents the base command when called without any subcommands
	rootCmd = &cobra.Command{
		Use:   "crowdstrike-falcon-downloader",
		Short: "Downloads the latest releases of the CrowdStrike Falcon Sensor agent.",
		Long: LongHelpText(`
		crowdstrike-falcon-downloader

		Downloads the latest releases of the CrowdStrike Falcon Sensor agent.
		Supports a variety of platforms and architectures, including Windows, macOS,
		and Linux.`),
		Run: func(cmd *cobra.Command, args []string) {
			verifyEnvironment()

			if fVerbose {
				logger.SetLevel(log.DebugLevel)
			}

			if fAmzn1 || fAmzn2 || fAmzn2023 || fEL6 || fEL7 || fEL8 || fEL9 || fMac || fSuse11 || fSuse12 ||
				fSuse15 || fDebian || fUbuntu || fWindows {
				hasOSFlag = true
			}

			if fArm64 || fIntel64 || fS390x {
				hasCPUFlag = true
			}

			err := spinner.New().
				Title("Fetching OAuth Bearer Token...").
				Type(spinner.Dots).
				Action(func(apiToken *string) func() {
					return func() {
						token, err := crowdstrike.ExchangeKeys(fVerbose)
						if err != nil {
							logger.Fatal("could not exchange keys", "err", err)
						}

						*apiToken = token
					}
				}(&apiToken)).
				Run()
			if err != nil {
				logger.Fatal(err)
			}

			logger.Debug("Successfully fetched OAuth Bearer Token.")

			err = spinner.New().
				Title("Fetching the list of Falcon sensors...").
				Type(spinner.Dots).
				Action(func(sensors *[]crowdstrike.ListResources) func() {
					return func() {
						data, err := crowdstrike.ListInstallers(apiToken, fVerbose)
						if err != nil {
							logger.Fatal("could not list the available installers", "err", err)
						}

						filteredData := filterData(data)

						// Sort by text
						slices.SortFunc(filteredData, func(a, b crowdstrike.ListResources) int {
							return cmp.Or(
								cmp.Compare(b.Version, a.Version),
								cmp.Compare(a.Name, b.Name),
							)
						})

						if fLatest && hasOSFlag && hasCPUFlag && len(filteredData) > 0 {
							*sensors = []crowdstrike.ListResources{
								filteredData[0],
							}
						} else if fLatest {
							logger.Fatal(
								"The --latest flag requires both an OS flag AND a CPU flag.",
								"hasOSFlag", hasOSFlag,
								"hasCPUFlag", hasCPUFlag,
								"results", len(filteredData),
							)
						} else {
							*sensors = filteredData
						}
					}
				}(&sensors)).
				Run()
			if err != nil {
				logger.Fatal(err)
			}

			logger.Debug("Successfully fetched the list of Falcon sensors...")

			if fDownload && len(sensors) == 1 {
				if sensors[0] != (crowdstrike.ListResources{}) {
					err = crowdstrike.DownloadInstaller(
						apiToken,
						sensors[0].Sha256,
						sensors[0].Name,
						sensors[0].FileSize,
					)
					if err != nil {
						logger.Fatal(err)
					}
				}

				os.Exit(0)
			}

			if fJson {
				jsonb, err := json.Marshal(sensors)
				if err != nil {
					logger.Fatal(err)
				}

				fmt.Println(string(jsonb))
			} else {
				columns := []table.Column{
					{Title: "Name", Width: 50},     // lint:allow_raw_number
					{Title: "Version", Width: 10},  // lint:allow_raw_number
					{Title: "OS", Width: 30},       // lint:allow_raw_number
					{Title: "SHA256", Width: 15},   // lint:allow_raw_number
					{Title: "Size", Width: 7},      // lint:allow_raw_number
					{Title: "Released", Width: 15}, // lint:allow_raw_number
				}

				rows := []table.Row{}

				for i := range sensors {
					rows = append(
						rows,
						table.Row{
							sensors[i].Name,
							sensors[i].Version,
							sensors[i].OS + " " + sensors[i].OSVersion,
							sensors[i].Sha256,
							humanize.Bytes(uint64(sensors[i].FileSize)),
							humanize.Time(sensors[i].ReleaseDate),
						},
					)

					sensorMap[sensors[i].Sha256] = sensors[i]
				}

				t := table.New(
					table.WithColumns(columns),
					table.WithRows(rows),
					table.WithFocused(true),
					table.WithHeight(height),
				)

				s := table.DefaultStyles()
				s.Header = s.Header.
					BorderStyle(lipgloss.NormalBorder()).
					BorderForeground(lipgloss.Color("240")).
					BorderBottom(true).
					Bold(false)
				s.Selected = s.Selected.
					Foreground(lipgloss.Color("229")).
					Background(lipgloss.Color("57")).
					Bold(false)
				t.SetStyles(s)

				m := model{
					table: t,
					keys:  keys,
					help:  help.New(),
				}
				if _, err := tea.NewProgram(m).Run(); err != nil {
					fmt.Println("Error running program:", err)
					os.Exit(1)
				}

				if sensor != (crowdstrike.ListResources{}) {
					err = crowdstrike.DownloadInstaller(apiToken, sensor.Sha256, sensor.Name, sensor.FileSize)
					if err != nil {
						logger.Fatal(err)
					}
				}
			}
		},
	}
)

func init() {
	rootCmd.PersistentFlags().
		BoolVarP(&fDownload, "download", "d", false, "Download the sensor when there is a single match.")
	rootCmd.PersistentFlags().
		BoolVarP(&fLatest, "latest", "l", false, "Determine the latest release for an OS + CPU combination.")
	rootCmd.PersistentFlags().BoolVarP(&fJson, "json", "j", false, "Enable JSON output.")
	rootCmd.PersistentFlags().BoolVarP(&fVerbose, "verbose", "v", false, "Enable verbose output.")

	rootCmd.Flags().BoolVarP(&fAmzn1, "amzn1", "", false, "Filter to include Amazon Linux 1 installers.")
	rootCmd.Flags().BoolVarP(&fAmzn2, "amzn2", "", false, "Filter to include Amazon Linux 2 installers.")
	rootCmd.Flags().BoolVarP(&fAmzn2023, "amzn2023", "", false, "Filter to include Amazon Linux 2023 installers.")
	rootCmd.Flags().BoolVarP(&fEL6, "el6", "", false, "Filter to include Enterprise Linux 6 installers.")
	rootCmd.Flags().BoolVarP(&fEL7, "el7", "", false, "Filter to include Enterprise Linux 7 installers.")
	rootCmd.Flags().BoolVarP(&fEL8, "el8", "", false, "Filter to include Enterprise Linux 8 installers.")
	rootCmd.Flags().BoolVarP(&fEL9, "el9", "", false, "Filter to include Enterprise Linux 9 installers.")
	rootCmd.Flags().BoolVarP(&fMac, "macos", "", false, "Filter to include macOS installers.")
	rootCmd.Flags().BoolVarP(&fSuse11, "suse11", "", false, "Filter to include Slackware/SUSE 11 installers.")
	rootCmd.Flags().BoolVarP(&fSuse12, "suse12", "", false, "Filter to include Slackware/SUSE 12 installers.")
	rootCmd.Flags().BoolVarP(&fSuse15, "suse15", "", false, "Filter to include Slackware/SUSE 15 installers.")
	rootCmd.Flags().BoolVarP(&fDebian, "debian", "", false, "Filter to include Debian installers.")
	rootCmd.Flags().BoolVarP(&fUbuntu, "ubuntu", "", false, "Filter to include Ubuntu LTS installers.")
	rootCmd.Flags().BoolVarP(&fWindows, "windows", "", false, "Filter to include Windows installers.")

	rootCmd.Flags().BoolVarP(&fArm64, "arm64", "", false, "Filter to include 64-bit ARM (arm64/aarch64) installers.")
	rootCmd.Flags().
		BoolVarP(&fIntel64, "intel64", "", false, "Filter to include 64-bit Intel-compat (amd64/x86_64) installers.")
	rootCmd.Flags().BoolVarP(&fS390x, "s390x", "", false, "Filter to include IBM zLinux (s390x) installers.")
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

type (
	model struct {
		help     help.Model
		lastKey  string
		keys     keyMap
		table    table.Model
		quitting bool
	}

	// keyMap defines a set of keybindings. To work for help it must satisfy
	// key.Map. It could also very easily be a map[string]key.Binding.
	keyMap struct {
		Up    key.Binding
		Down  key.Binding
		Help  key.Binding
		Enter key.Binding
		Quit  key.Binding
	}
)

// ShortHelp returns keybindings to be shown in the mini help view. It's part
// of the key.Map interface.
func (k keyMap) ShortHelp() []key.Binding { // lint:allow_large_memory // Implementing a model I have no control over.
	return []key.Binding{
		k.Help,
		k.Enter,
		k.Quit,
	}
}

// FullHelp returns keybindings for the expanded help view. It's part of the
// key.Map interface.
func (k keyMap) FullHelp() [][]key.Binding { // lint:allow_large_memory // Implementing a model I have no control over.
	return [][]key.Binding{
		{ // first column
			k.Up,
			k.Down,
		},
		{ // second column
			k.Help,
			k.Quit,
		},
		{ // third column
			k.Enter,
		},
	}
}

func (m model) Init() tea.Cmd { // lint:allow_large_memory // Implementing a model I have no control over.
	return nil
}

func (m model) Update( // lint:allow_large_memory // Implementing a model I have no control over.
	msg tea.Msg,
) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// If we set a width on the help menu it can gracefully truncate
		// its view as needed.
		m.help.Width = msg.Width

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Up):
			m.lastKey = "↑"
		case key.Matches(msg, m.keys.Down):
			m.lastKey = "↓"
		case key.Matches(msg, m.keys.Help):
			m.help.ShowAll = !m.help.ShowAll
		case key.Matches(msg, m.keys.Enter):
			m.quitting = true
			sensor = sensorMap[m.table.SelectedRow()[3]]

			return m, tea.Quit
		case key.Matches(msg, m.keys.Quit):
			m.quitting = true

			return m, tea.Quit
		}
	}

	m.table, cmd = m.table.Update(msg)

	return m, cmd
}

func (m model) View() string { // lint:allow_large_memory // Implementing a model I have no control over.
	if m.quitting {
		return ""
	}

	helpView := m.help.View(m.keys)

	return baseStyle.Render(m.table.View()) + "\n" + helpView
}
