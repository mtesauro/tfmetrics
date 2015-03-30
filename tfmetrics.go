// tfmetrics.go
package main

import (
	"fmt"
	tf "github.com/mtesauro/tfclient"
	"net/http"
	"os"
	"time"
)

// Metrics functions
func createSummary(teams *tf.TeamResp) {
	// Create summary data across all teams/apps
	for _, v := range teams.Tm {
		// Count the number of apps per team plus overall count of apps
		teamCounts[v.Name] = len(v.Apps)
		appCount += len(v.Apps)

		// For apps with criticals, pull out them plus the count
		if v.NumCrit > 0 {
			critApps[v.Name] = v.NumCrit
		}
	}

	return
}

func getTeams(tfc *http.Client, t *tf.TeamResp) {
	tResp, err := tf.GetTeams(tfc)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}

	// Setup Team struct to hold the data we received
	tf.MakeTeamStruct(t, tResp)

	return
}

func currentMonth() time.Month {
	return time.Now().Month()
}

func sumMonth(m *tfMonth) {
	m.quarter = "Q1-2015"
}

func currentQuarter(time.Month) string {
	return "Q1-2015"
}

func previoiusQuarter(pQ *tfQuarter) string {
	return "Q4-2014"
}

func sumQuarter(m1 *tfMonth, m2 *tfMonth, m3 *tfMonth, q *tfQuarter) {
	q.qLabel = "Q1-2015"
}

func sumYear(q1 *tfQuarter, q2 *tfQuarter, q3 *tfQuarter, q4 *tfQuarter, y *tfYear) {
	y.year = 2015
}

func main() {
	// Create a client to talk to the API
	tfc, err := tf.CreateClient()
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}

	// Gather summary metrics
	var teams tf.TeamResp
	getTeams(tfc, &teams)
	createSummary(&teams)

	// Gather trending metrics
	curMon := currentMonth()
	fmt.Printf("Current Month is %+v\n\n", curMon)

	// Print the metrics we've gathered so far to screen
	// Eventually move this to a file so it can be emailed
	fmt.Println("")
	fmt.Printf("Total Apps is %v\n", appCount)
	//fmt.Printf("Team counts is %+v\n\n", teamCounts)
	// TODO Add sort by value to teamCounts
	fmt.Println("Individual team counts are:")
	for i, v := range teamCounts {
		fmt.Printf("  %v includes %v apps\n", i, v)
	}
	fmt.Println("")
	fmt.Printf("Total Apps with crits is %v\n", len(critApps))
	//fmt.Printf("Apps with crits is %+v\n\n", critApps)
	// If there's apps with crits, print them and the average
	if len(critApps) > 0 {
		// TODO Add sort by value to critApps
		fmt.Println("Apps with crits are:")
		for i, v := range critApps {
			fmt.Printf("  %v has %v crit findings\n", i, v)
		}
		percntCrits := (float64(len(critApps)) / float64(appCount)) * 100
		fmt.Printf("Percentage of apps with crits is %.2f %%\n\n", percntCrits)
	}

	fmt.Println("")

	//// Before searching you must setup a default Search Struct
	//srch := tf.CreateSearchStruct()
	//// Restrict default search to Q1 2015
	////tf.StartSearch(&srch, "01/01/2015")
	////tf.EndSearch(&srch, "03/31/2015")
	//// And only ask for criticals
	//tf.SeveritySearch(&srch, 5)
	//// Increase the default number of results up from 10
	//tf.NumSearchResults(&srch, 800)
	////                  seems to die at 488 results
	//// Only open vulns
	//tf.ShowInSearch(&srch, "open")
	//// Send the search query to TF
	//vulns, err := tf.VulnSearch(tfc, &srch)
	//if err != nil {
	//	fmt.Print(err)
	//	os.Exit(1)
	//}
	////fmt.Printf("\nvulns is %+v\n\n", vulns)
	//// Create a search struct and load it with the search with just conducted
	//var search tf.SrchResp
	////os.Exit(0)
	//err = tf.MakeSearchStruct(&search, vulns)
	//if err != nil {
	//	fmt.Print(err)
	//	os.Exit(1)
	//}
	//fmt.Printf("\nQ1 total crit count is %+v \n\n", len(search.Results))
}
