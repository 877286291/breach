/*
Copyright © 2024 Aurora 877286291@qq.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"breach/internal/poc"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var target string
var file string
var pocType string

// pocCmd represents the poc command
var pocCmd = &cobra.Command{
	Use:   "poc",
	Short: "Performing POCs on the target URL",
	Run: func(cmd *cobra.Command, args []string) {
		if !cmd.HasFlags() {
			fmt.Println("Error: Please specify a target URL using -t or -f")
			return
		}
		pocTypes := strings.Split(pocType, ",")
		if target != "" {
			newPoc, err := poc.NewPoc(target, pocTypes)
			if err != nil {
				fmt.Println(err)
				return
			}
			for _, payload := range newPoc.Payloads {
				response := payload.CheckVul()
				fmt.Printf("%s\t%s\n", target, response.Message)
			}
		} else {
			fullPath, err := filepath.Abs(file)
			bytes, err := os.ReadFile(fullPath)
			if err != nil {
				fmt.Println(err)
			}
			fileContent := string(bytes)
			lines := strings.Split(fileContent, "\n")
			w := sync.WaitGroup{}
			for _, line := range lines {
				if strings.TrimSpace(line) != "" {
					w.Add(1)
					go func(t string) {
						newPoc, err := poc.NewPoc(t, pocTypes)
						if err != nil {
							fmt.Println(err)
							return
						}
						for _, payload := range newPoc.Payloads {
							response := payload.CheckVul()
							fmt.Printf("%s\t%s\n", t, response.Message)
						}
						w.Done()
					}(line)
				}
			}
			w.Wait()
		}
	},
}

func init() {
	scanCmd.AddCommand(pocCmd)
	pocCmd.Flags().StringVarP(&target, "target", "t", "", "target URL")
	pocCmd.Flags().StringVarP(&file, "file", "f", "", "batch target URLs")
	pocCmd.Flags().StringVarP(&pocType, "poc-type", "", "ALL", "POC type: ALL, Thinkphp")
}
