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
	// Check that time stamp is set before summing the month as its required
	if m.tStamp.Year() == 1 {
		fmt.Println("Error:  You must set the timestamp - tfMonth.tStamp - before calling sumMonth")
		os.Exit(1)
	}

	m.quarter = getQuarter(m.tStamp.Month(), m.tStamp.Year())

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
	// TODO - add an option to only pull CWEs of 1+ severity level(s)
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
	sApps := sortCounts(apps, true)

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
// if reverse is set to true, it will be ascending. iterate over the initial int in
// order e.g. for j := 0; j < len(sortedMap); j++ {} and use
// for k, v := range sortedMap[j] {} to acess the values in desc/asc order
func sortCounts(m map[string]int, ascending bool) map[int]map[string]int {
	sorted := make(map[int]map[string]int)

	// Fill up the sorted map
	count := 0
	for k, v := range m {
		sorted[count] = map[string]int{k: v}
		count++
	}

	// Bubble sort the counts in newly populated sorted map
	for cnt := len(sorted) - 1; ; cnt-- {
		changed := false
		for index := 0; index < cnt; index++ {
			if mapCompare(sorted[index], sorted[index+1], ascending) {
				sorted[index], sorted[index+1] = sorted[index+1], sorted[index]
				changed = true
			}
		}
		if changed == false {
			break
		}
	}

	return sorted
}

func mapCompare(a map[string]int, b map[string]int, ascending bool) bool {
	for _, v1 := range a {
		for _, v2 := range b {
			if ascending {
				if v1 > v2 {
					return true
				} else {
					return false
				}
			} else {
				// Descending
				if v1 < v2 {
					return true
				} else {
					return false
				}
			}
		}
	}

	return true
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

func sumQuarter(m0 *tfMonth, q *tfQuarter) {
	q.qLabel = m0.quarter
	q.qTStamps = [3]time.Time{
		m0.tStamp,
		previousMonth(m0.tStamp),
		previousMonth(previousMonth(m0.tStamp)),
	}
	// Gather data for the previous 2 months
	var m1, m2 tfMonth
	m1.tStamp = q.qTStamps[1]
	m2.tStamp = q.qTStamps[2]
	sumMonth(&m1)
	sumMonth(&m2)

	// tfMonth structs for the quarter
	q.months = [3]*tfMonth{
		m0,
		&m1,
		&m2,
	}

	// Total vulns, crit & high counts and percentages
	q.totVulns = m0.totVulns + m1.totVulns + m2.totVulns
	q.critApps = sumMaps(m0.critApps, m1.critApps, m2.critApps)
	q.highApps = sumMaps(m0.highApps, m1.highApps, m2.highApps)
	q.percntCrit = (float64(len(q.critApps)) / float64(appCount)) * 100
	q.percntHigh = (float64(len(q.highApps)) / float64(appCount)) * 100

	// Best and Worst apps
	q.bestApps = sumMaps(m0.bestApps, m1.bestApps, m2.bestApps)
	q.worstApps = sumMaps(m0.worstApps, m1.worstApps, m2.worstApps)

	// Tool Usage
	q.toolUsage = sumMaps(m0.toolUsage, m1.toolUsage, m2.toolUsage)

	// Top 10 CWE's
	q.topCWE = sumMaps(m0.topCWE, m1.topCWE, m2.topCWE)
}

func sumMaps(s ...map[string]int) map[string]int {
	tot := make(map[string]int)

	// Cycle through the maps sent and sum them up using the int as a count of
	// occurances of the string
	for _, v := range s {
		for app, cnt := range v {
			tot = sumApps(tot, app, cnt)
		}
	}

	return tot
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
	fmt.Println("Gathering summary metrics...")
	var teams tf.TeamResp
	getTeams(tfc, &teams)
	createSummary(&teams)

	// Gather trending metrics starting with current month, quarter & year

	fmt.Println("Gathering month metrics...")
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
	m0.tStamp = time.Date(2015, time.Month(2), 28, 0, 0, 0, 0, time.UTC)
	// CHEATING END

	// Gather data for the month
	sumMonth(&m0)

	// Gather metrics for the previous quarter
	// TODO - Do partial and last full or just last full or just the partial?
	fmt.Println("Gethering quarter metrics...")
	var q0 tfQuarter
	sumQuarter(&m0, &q0)

	//os.Exit(0)

	// Print the metrics we've gathered so far to screen
	// Eventually move this to a file so it can be emailed
	fmt.Println("")
	fmt.Println("==========[Summary Metrics]==========")
	fmt.Printf("Total Apps in ThreadFix is %v\n", appCount)
	fmt.Printf("Number of LoB/Teams in Threadfix is %v\n", len(teamCounts))
	fmt.Println("Individual LoB/Team counts are:")
	sTeamCts := sortCounts(teamCounts, false)
	for j := 0; j < len(sTeamCts); j++ {
		for k, v := range sTeamCts[j] {
			fmt.Printf("  %v includes %v apps\n", k, v)
		}
	}
	fmt.Println("")
	fmt.Printf("Total LoB/Team with critical findings is %v\n", len(critsByLob))
	// If there's apps with crits, print them and the average
	if len(critsByLob) > 0 {
		fmt.Println("LoB with critical findings are:")
		sCritsLob := sortCounts(critsByLob, false)
		for j := 0; j < len(sCritsLob); j++ {
			for k, v := range sCritsLob[j] {
				fmt.Printf("  %v has %v critical findings\n", k, v)
			}
		}
		percntCrits := (float64(len(critsByLob)) / float64(appCount)) * 100
		fmt.Printf("Percentage of LoB/Teams with critical findings is %.2f%%\n\n", percntCrits)
	}

	// Monthly stats
	fmt.Println("")
	fmt.Println("==========[Month Metrics]==========")
	fmt.Printf("Metrics for %+v %+v", m0.tStamp.Month(), m0.tStamp.Year())
	fmt.Printf(", which is part of %+v\n", m0.quarter)
	fmt.Printf("Total vulnerabilities found for %+v was %+v\n", m0.tStamp.Month(), m0.totVulns)
	// Criticals
	if len(m0.critApps) > 0 {
		fmt.Printf("Total apps with critical findings is %+v\n", len(m0.critApps))
		fmt.Println("Individual App critical finding counts are:")
		sMCrit := sortCounts(m0.critApps, false)
		for j := 0; j < len(sMCrit); j++ {
			for k, v := range sMCrit[j] {
				fmt.Printf("  %v has %v critical findings\n", k, v)
			}
		}
		fmt.Printf("Percentage of Apps with critical findings is %.2f%%\n\n", m0.percntCrit)
	}
	// Highs
	if len(m0.highApps) > 0 {
		fmt.Printf("Total apps with highs is %+v\n", len(m0.highApps))
		fmt.Println("Individual App high finding counts are:")
		sMHigh := sortCounts(m0.highApps, false)
		for j := 0; j < len(sMHigh); j++ {
			for k, v := range sMHigh[j] {
				fmt.Printf("  %v has %v critical findings\n", k, v)
			}
		}
		fmt.Printf("Percentage of Apps with high findings is %.2f%%\n\n", m0.percntHigh)
	}
	// Best apps
	fmt.Println("The best apps of the month (and their score) are: (smaller is better)")
	sBest := sortCounts(m0.bestApps, true)
	for j := 0; j < len(sBest); j++ {
		for k, v := range sBest[j] {
			fmt.Printf("  %v has a score of %v \n", k, v)
		}
	}
	// Worst apps
	fmt.Println("The worst apps of the month (and their score) are: (smaller is better)")
	sWorst := sortCounts(m0.worstApps, false)
	for j := 0; j < len(sWorst); j++ {
		for k, v := range sWorst[j] {
			fmt.Printf("  %v has a score of %v \n", k, v)
		}
	}
	// Tool usage
	fmt.Printf("Number of assessments by type for %+v %+v\n", m0.tStamp.Month(), m0.tStamp.Year())
	sTools := sortCounts(m0.toolUsage, false)
	for j := 0; j < len(sTools); j++ {
		for k, v := range sTools[j] {
			fmt.Printf("  %v found %v results\n", k, v)
		}
	}
	// Top 10 CWEs
	fmt.Printf("The Top 10 CWE Vulnerabilities for %+v %+v\n", m0.tStamp.Month(), m0.tStamp.Year())
	sCwe := sortCounts(m0.topCWE, false)
	max := 10
	if len(sCwe) < max {
		max = len(sCwe)
	}
	for j := 0; j < max; j++ {
		for k, v := range sCwe[j] {
			fmt.Printf("  %v occurrences of %v\n", v, k)
		}
	}

	// Quarterly stats
	fmt.Println("")
	fmt.Println("==========[Quarter Metrics]==========")
	fmt.Printf("Metrics for %+v\n", q0.qLabel)
	fmt.Printf("Total vulnerabilities found for %+v was %+v\n", q0.qLabel, q0.totVulns)
	// Criticals
	if len(q0.critApps) > 0 {
		fmt.Printf("Total apps with critical findings is %+v\n", len(q0.critApps))
		fmt.Println("Individual App critical finding counts are:")
		sQCrit := sortCounts(q0.critApps, false)
		for j := 0; j < len(sQCrit); j++ {
			for k, v := range sQCrit[j] {
				fmt.Printf("  %v has %v critical findings\n", k, v)
			}
		}
		fmt.Printf("Percentage of Apps with critical findings is %.2f%%\n\n", q0.percntCrit)
	}
	// Highs
	if len(q0.highApps) > 0 {
		fmt.Printf("Total apps with highs is %+v\n", len(q0.highApps))
		fmt.Println("Individual App high finding counts are:")
		sQHigh := sortCounts(q0.highApps, false)
		for j := 0; j < len(sQHigh); j++ {
			for k, v := range sQHigh[j] {
				fmt.Printf("  %v has %v critical findings\n", k, v)
			}
		}
		fmt.Printf("Percentage of Apps with high findings is %.2f%%\n\n", q0.percntHigh)
	}
	// Best apps
	fmt.Printf("The best apps of %+v (and their score) are: (smaller is better)\n", q0.qLabel)
	sQBest := sortCounts(q0.bestApps, true)
	for j := 0; j < len(sQBest); j++ {
		for k, v := range sQBest[j] {
			fmt.Printf("  %v has a score of %v \n", k, v)
		}
	}
	// Worst apps
	fmt.Printf("The worst apps of %+v (and their score) are: (smaller is better)\n", q0.qLabel)
	sQWorst := sortCounts(q0.worstApps, false)
	for j := 0; j < len(sQWorst); j++ {
		for k, v := range sQWorst[j] {
			fmt.Printf("  %v has a score of %v \n", k, v)
		}
	}
	// Tool usage
	fmt.Printf("Number of assessments by type for %+v\n", q0.qLabel)
	sQTools := sortCounts(q0.toolUsage, false)
	for j := 0; j < len(sQTools); j++ {
		for k, v := range sQTools[j] {
			fmt.Printf("  %v found %v results\n", k, v)
		}
	}
	// Top 10 CWEs
	fmt.Printf("The Top 10 CWE Vulnerabilities for %+v\n", q0.qLabel)
	sQCwe := sortCounts(q0.topCWE, false)
	max = 10
	if len(sQCwe) < max {
		max = len(sQCwe)
	}
	for j := 0; j < max; j++ {
		for k, v := range sQCwe[j] {
			fmt.Printf("  %v occurrences of %v\n", v, k)
		}
	}

	fmt.Println("")
	fmt.Println("Done.")
}
