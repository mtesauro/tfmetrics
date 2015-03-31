// tfmetrics.go
package main

import (
	"fmt"
	tf "github.com/mtesauro/tfclient"
	"net/http"
	"os"
	"strconv"
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
	// Call Get Team API method
	tResp, err := tf.GetTeams(tfc)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}

	// Setup Team struct to hold the data we received
	tf.MakeTeamStruct(t, tResp)

	return
}

func currentQuarter(m time.Month, y int) string {

	return qtrDefs[int(m)] + "-" + strconv.Itoa(y)
}

func sumMonth(m *tfMonth) {
	// the partials defaults to false, set it true if needed
	if m.tStamp.Day() != lastDate(int(m.tStamp.Month()), m.tStamp.Year()) {
		m.mpartial = true
		// since the month is partial, the quarter must be too
		m.qpartial = true
	}

	// If m.partial is false, check that we're in the last month of the quarter
	if m.mpartial == false && lastMonth(int(m.tStamp.Month())) {
		// The month is full and we're in the last montn of a quarter
		m.qpartial = false
	}

	// Create a search struct to hold 1 month worth of data to mine and populate
	var search tf.SrchResp
	monthSearch(m.tStamp, &search)
	m.totVulns = len(search.Results)

	// Find the apps with criticals aka int 5
	m.critApps = appsWithVulns(5, &search)

	// Find the apps with highs aka int 4
	//m.critApps = appsWithVulns(4, &search)

	return
}

func monthSearch(t time.Time, srch *tf.SrchResp) {
	// Create a struct to hold our search parameters
	s := tf.CreateSearchStruct()

	// Restrict default search to the month sent
	st := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	start := st.Format("01/02/2006")
	e := time.Date(t.Year(), t.Month(), lastDate(int(t.Month()), t.Year()), 0, 0, 0, 0, time.UTC)
	end := e.Format("01/02/2006")
	tf.StartSearch(&s, start)
	tf.EndSearch(&s, end)
	// And only ask for all but infos - 5, 4, 3, 2
	tf.SeveritySearch(&s, 5, 4, 3, 2)
	// Increase the default number of results up from 10
	tf.NumSearchResults(&s, 1500)
	// Only open vulns
	tf.ShowInSearch(&s, "open")
	// Send the search query to TF
	vulns, err := tf.VulnSearch(tfc, &s)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}

	// Create a search struct and load it with the search with just conducted
	err = tf.MakeSearchStruct(srch, vulns)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}
}

func appsWithVulns(sev int, srch *tf.SrchResp) map[string]int {
	apps := make(map[string]int)

	return apps
}

func lastDate(month int, year int) int {
	// Using a month and year, return the last day for that month
	// Add a month to what is sent, subtract an hour,
	// and that date is the last day of the month
	if month == 12 {
		year += 1
	}
	month += 1

	t := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)

	prev := t.Add(-time.Hour)

	return prev.Day()
}

func lastMonth(m int) bool {
	// Determine if we're in the last month of a quarter
	// Look in quarterEnds to see if month sent is matchs, return true if so
	for _, v := range quarterEnd {
		if v == m {
			return true
		}
	}

	return false
}

func previoiusQuarter(pQ *tfQuarter) string {
	return "Q4-2024"
}

func sumQuarter(m1 *tfMonth, m2 *tfMonth, m3 *tfMonth, q *tfQuarter) {
	q.qLabel = "Q1-2025"
}

func sumYear(q1 *tfQuarter, q2 *tfQuarter, q3 *tfQuarter, q4 *tfQuarter, y *tfYear) {
	y.year = 2025
}

func main() {
	// Create a client to talk to the API and set it as a global variable
	t, err := tf.CreateClient()
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}
	tfc = t

	// Gather summary metrics
	var teams tf.TeamResp
	getTeams(tfc, &teams)
	createSummary(&teams)

	// Gather trending metrics starting with current month & year

	// Fill in current month's stats
	var m0 tfMonth
	m0.tStamp = time.Now()
	curQua := currentQuarter(m0.tStamp.Month(), m0.tStamp.Year())
	m0.quarter = curQua
	// Fill in the rest of the month
	sumMonth(&m0)

	// Check to see if current quarter is partial of complete

	fmt.Printf("Current Day is %+v\n", m0.tStamp.Day())
	fmt.Printf("Current Month is %+v\n", m0.tStamp.Month())
	fmt.Printf("Current month as an int is %d\n", int(m0.tStamp.Month()))
	fmt.Printf("Current Quarter is %+v\n", curQua)
	fmt.Printf("Current Year is %+v\n", m0.tStamp.Year())
	fmt.Printf("\nMonth 0 is %+v\n", m0)

	fmt.Println()
	// shortcircuit the code
	os.Exit(0)

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
	//fmt.Printf("\nQ1 total vuln count is %+v \n\n", len(search.Results))
}
