// tfmetrics.go
package main

import (
	"fmt"
	tf "github.com/mtesauro/tfclient"
	"net/http"
	"os"
	"sort"
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
			critsByLob[v.Name] = v.NumCrit
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
	m.highApps = appsWithVulns(4, &search)

	// Calculate precent crit and high
	m.percntCrit = (float64(len(m.critApps)) / float64(appCount)) * 100
	m.percntHigh = (float64(len(m.highApps)) / float64(appCount)) * 100

	// Best and Worst apps
	m.bestApps, m.worstApps = rateApps(&search)

	// Tool Usage
	m.toolUsage = toolUsage(&search)

	// Top 10 CWE's
	m.topCWE = cweCounts(&search)

	return
}

func cweCounts(srch *tf.SrchResp) map[string]int {
	cwes := make(map[string]int)

	// Cycle through the results struct, pulling out the tools which found vulns
	for k, _ := range srch.Results {
		c := "CWE-" + strconv.Itoa(srch.Results[k].CweVuln.Id) +
			": " + srch.Results[k].CweVuln.Name
		cwes = sumApps(cwes, c, 1)
	}

	return cwes
}

func toolUsage(srch *tf.SrchResp) map[string]int {
	tools := make(map[string]int)

	// Cycle through the results struct, pulling out the tools which found vulns
	for k, _ := range srch.Results {
		for i := 0; i < len(srch.Results[k].Scanners); i++ {
			t := srch.Results[k].Scanners[i]
			tools = sumApps(tools, t, 1)
		}
	}

	//fmt.Printf("Tools count is %+v\n", tools)
	return tools
}

func rateApps(srch *tf.SrchResp) (map[string]int, map[string]int) {
	apps := make(map[string]int)

	// Cycle through the results struct, pulling out the severity level sent in
	for k, _ := range srch.Results {
		switch srch.Results[k].Severity.Value {
		case 5:
			// Critical
			sumApps(apps, srch.Results[k].Apps.Name, vulnWeight[5])
		case 4:
			// High
			sumApps(apps, srch.Results[k].Apps.Name, vulnWeight[4])
		case 3:
			// Medium
			sumApps(apps, srch.Results[k].Apps.Name, vulnWeight[3])
		case 2:
			// Low
			sumApps(apps, srch.Results[k].Apps.Name, vulnWeight[2])
		}
	}

	// Sort apps and pull off top 10 and bottom 10
	sApps := countSorted(apps, true)

	var l, bestEnd, worseStart int
	l = len(sApps)
	if l/2 < 10 {
		if l%2 == 0 {
			bestEnd = l / 2
			worseStart = l / 2
		} else {
			bestEnd = (l-1)/2 + 1
			worseStart = (l + 1) / 2
		}
	} else {
		bestEnd = 11
		worseStart = len(sApps) - 10
	}

	best := make(map[string]int)
	for b := 0; b < bestEnd; b++ {
		for k, v := range sApps[b] {
			best[k] = v
		}
	}

	worse := make(map[string]int)
	for w := worseStart; w < len(sApps); w++ {
		for k, v := range sApps[w] {
			worse[k] = v
		}
	}

	return best, worse
}

func sumApps(a map[string]int, name string, val int) map[string]int {
	// Takes a map and add val (value) to the int counter of map[string]int
	// Sums up values under a label - usually an app name
	if _, ok := a[name]; ok {
		a[name] = a[name] + val
	} else {
		a[name] = val
	}

	return a
}

// Custom function to return a sorted map[int]map[string]int descending by default
// if reverse is set to true, it will be ascending
func countSorted(m map[string]int, ascending bool) map[int]map[string]int {
	// Invert sent map
	invMap := make(map[int]string, len(m))
	for k, v := range m {
		invMap[v] = k
	}

	var keys []int
	for k := range invMap {
		keys = append(keys, k)
	}

	if ascending {
		sort.Ints(keys)
	} else {
		sort.Sort(sort.Reverse(sort.IntSlice(keys)))
	}

	// Create a new map and return it
	sorted := make(map[int]map[string]int)
	for i, k := range keys {
		sorted[i] = map[string]int{invMap[k]: k}
	}

	return sorted
}

// End custom sort fuctions

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
	// Increase number of results up from the default of 10
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

	// Cycle through the results struct, pulling out the severity level sent in
	for k, _ := range srch.Results {
		if srch.Results[k].Severity.Value == sev {
			apps = sumApps(apps, srch.Results[k].Apps.Name, 1)
		}
	}

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

func previousMonth(n time.Time) time.Time {
	d := lastDate(int(n.Month()-1), n.Year())
	return time.Date(n.Year(), time.Month(n.Month()-1), d, 0, 0, 0, 0, time.UTC)
}

func getQuarter(m time.Month, y int) string {

	return qtrDefs[int(m)] + "-" + strconv.Itoa(y)
}

func sumQuarter(lastMo *tfMonth, q *tfQuarter) {
	q.qLabel = lastMo.quarter
	q.qTStamps = [3]time.Time{
		lastMo.tStamp,
		time.Now(),
		time.Now(),
	}

}

func sumYear(lastQtr *tfQuarter, y *tfYear) {
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

	// Gather trending metrics starting with current month, quarter & year

	// Fill in current month's stats
	var m0 tfMonth
	n := time.Now()
	// If current day is less then monthCutoff, then back up a month for metrics
	if n.Day() <= monthCutoff {
		m0.tStamp = previousMonth(n)
	} else {
		m0.tStamp = n
	}
	// CHEATING AND FIXING THE MONTH TO BE MARCH 30, 2015
	m0.tStamp = time.Date(2015, time.Month(3), 30, 0, 0, 0, 0, time.UTC)
	// CHEATING END
	curQua := getQuarter(m0.tStamp.Month(), m0.tStamp.Year())
	m0.quarter = curQua
	// Fill in the rest of the month
	sumMonth(&m0)

	// Gather metrics for the previous quarter
	// TODO - Do partial and last full or just last full or just the partial?
	var q0 tfQuarter
	sumQuarter(&m0, &q0)

	fmt.Printf("Current Day is %+v\n", m0.tStamp.Day())
	fmt.Printf("Current Month is %+v\n", m0.tStamp.Month())
	fmt.Printf("Current month as an int is %d\n", int(m0.tStamp.Month()))
	fmt.Printf("Current Quarter is %+v\n", curQua)
	fmt.Printf("Current Year is %+v\n", m0.tStamp.Year())
	fmt.Printf("\nQuarter 0 is %+v\n", q0)

	fmt.Println()
	// shortcircuit the code
	os.Exit(0)

	// Print the metrics we've gathered so far to screen
	// Eventually move this to a file so it can be emailed
	fmt.Println("")
	fmt.Printf("Total Apps is %v\n", appCount)
	fmt.Println("Individual team counts are:")
	sTeamCts := countSorted(teamCounts, false)
	for j := 0; j < len(sTeamCts); j++ {
		for k, v := range sTeamCts[j] {
			fmt.Printf("  %v includes %v apps\n", k, v)
		}
	}
	fmt.Println("")
	//os.Exit(0)
	fmt.Println("Double check the below - count doesn't match and is it apps or LoB?")
	fmt.Printf("Total LoB with crits is %v\n", len(critsByLob))
	// If there's apps with crits, print them and the average
	if len(critsByLob) > 0 {
		fmt.Println("LoB with crits are:")
		sCritsLob := countSorted(critsByLob, false)
		for j := 0; j < len(sCritsLob); j++ {
			for k, v := range sCritsLob[j] {
				fmt.Printf("  %v has %v crit findings\n", k, v)
			}
		}
		percntCrits := (float64(len(critsByLob)) / float64(appCount)) * 100
		fmt.Printf("Percentage of apps with crits is %.2f%%\n\n", percntCrits)
	}

	fmt.Println("")
	fmt.Println("Done.")
}
