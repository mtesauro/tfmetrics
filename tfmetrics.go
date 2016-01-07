// tfmetrics.go
package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	tf "github.com/mtesauro/tfclient"
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
	err = tf.MakeTeamStruct(t, tResp)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}

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

	// Find Total vuns per month, vuln counts by LoB/Team, assessments by LoB/Team
	// and Total assessments for the month
	m.totVulns = len(search.Results)
	m.vulnByLob, m.assessByLob = lobCounts(&search)
	m.totAssess = totalMap(m.assessByLob)

	// Find the apps with criticals aka int 5
	m.critApps = appsWithVulns(5, &search)

	// Find the apps with highs aka int 4
	m.highApps = appsWithVulns(4, &search)

	// Calculate precent crit and high
	m.percntCrit = (float64(len(m.critApps)) / float64(appCount)) * 100
	m.percntHigh = (float64(len(m.highApps)) / float64(appCount)) * 100

	// Best and Worst apps and counts
	m.bestApps, m.worstApps = rateApps(&search)
	m.bAppsCnt = appVulnCounts(&search, m.bestApps)
	m.wAppsCnt = appVulnCounts(&search, m.worstApps)

	// Tool Usage
	m.toolUsage = toolUsage(&search)

	// Top 10 CWE's
	m.topCWE = cweCounts(&search)

	return
}

func totalMap(a map[string]int) int {
	t := 0
	for _, v := range a {
		t += v
	}

	return t
}

func appVulnCounts(srch *tf.SrchResp, a map[string]int) map[string]VulnCount {
	vul := make(map[string]VulnCount)

	// Cycle through the results struct, pulling out the vuln counts and apps assessed
	for k, _ := range srch.Results {
		// If the app name in these results is a key in the map sent in, do some sums
		if _, ok := a[srch.Results[k].Apps.Name]; ok {
			switch srch.Results[k].Severity.Value {
			case 5:
				// Critical
				sumVulns(vul, srch.Results[k].Apps.Name, 5)
			case 4:
				// High
				sumVulns(vul, srch.Results[k].Apps.Name, 4)
			case 3:
				// Medium
				sumVulns(vul, srch.Results[k].Apps.Name, 3)
			case 2:
				// Low
				sumVulns(vul, srch.Results[k].Apps.Name, 2)
			}
		}
	}

	return vul
}

func getAppId(teams *tf.TeamResp, n string) (int, error) {
	appId := 0

	for _, t := range teams.Tm {
		for _, v := range t.Apps {
			if v.Name == n {
				return v.Id, nil
			}
		}
	}

	msg := fmt.Sprintf("Unable to find an AppID for %s", n)

	return appId, errors.New(msg)
}

func lobCounts(srch *tf.SrchResp) (map[string]VulnCount, map[string]int) {
	vul := make(map[string]VulnCount)
	assess := make(map[string]int)
	appSeen := make(map[string]bool)

	// Cycle through the results struct, pulling out the vuln counts and apps assessed
	for k, _ := range srch.Results {
		switch srch.Results[k].Severity.Value {
		case 5:
			// Critical
			sumVulns(vul, srch.Results[k].Team.Name, 5)
		case 4:
			// High
			sumVulns(vul, srch.Results[k].Team.Name, 4)
		case 3:
			// Medium
			sumVulns(vul, srch.Results[k].Team.Name, 3)
		case 2:
			// Low
			sumVulns(vul, srch.Results[k].Team.Name, 2)
		}
		switch srch.Results[k].Severity.Value {
		case 5, 4, 3, 2, 1:
			a := srch.Results[k].Apps.Name
			if _, ok := appSeen[a]; ok {
				appSeen[a] = true
			} else {
				appSeen[a] = false
			}
			if appSeen[a] != true {
				t := srch.Results[k].Team.Name
				sumApps(assess, t, 1)
			}
		}
	}

	return vul, assess
}

func sumVulns(a map[string]VulnCount, name string, sev int) {
	//Takes a map and add one to the int counter of matching vul type in the
	//VulnCount struct under an app's name
	if _, ok := a[name]; ok {
		c := a[name].crit
		h := a[name].high
		m := a[name].med
		l := a[name].low

		switch sev {
		case 5:
			c++
			a[name] = VulnCount{c, h, m, l}
		case 4:
			h++
			a[name] = VulnCount{c, h, m, l}
		case 3:
			m++
			a[name] = VulnCount{c, h, m, l}
		case 2:
			l++
			a[name] = VulnCount{c, h, m, l}
		}
	} else {
		// First time we've seen a[name]
		switch sev {
		case 5:
			a[name] = VulnCount{1, 0, 0, 0}
		case 4:
			a[name] = VulnCount{0, 1, 0, 0}
		case 3:
			a[name] = VulnCount{0, 0, 1, 0}
		case 2:
			a[name] = VulnCount{0, 0, 0, 1}
		}
	}
}

func cweCounts(srch *tf.SrchResp) map[string]int {
	// TODO - add an option to only pull CWEs of 1+ severity level(s)
	cwes := make(map[string]int)

	// Cycle through the results struct, pulling out the tools which found vulns
	for k, _ := range srch.Results {
		c := "CWE-" + strconv.Itoa(srch.Results[k].CweVuln.Id) +
			": " + srch.Results[k].CweVuln.Name
		sumApps(cwes, c, 1)
	}

	return cwes
}

func toolUsage(srch *tf.SrchResp) map[string]int {
	tools := make(map[string]int)

	// Cycle through the results struct, pulling out the tools which found vulns
	for k, _ := range srch.Results {
		for i := 0; i < len(srch.Results[k].Scanners); i++ {
			t := srch.Results[k].Scanners[i]
			sumApps(tools, t, 1)
		}
	}

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

func sumApps(a map[string]int, name string, val int) {
	// Takes a map and add val (value) to the int counter of map[string]int
	// Sums up values under a label - usually an app name
	if _, ok := a[name]; ok {
		a[name] = a[name] + val
	} else {
		a[name] = val
	}
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
			sumApps(apps, srch.Results[k].Apps.Name, 1)
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
			sumApps(tot, app, cnt)
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
	//m0.tStamp = time.Date(2015, time.Month(2), 28, 0, 0, 0, 0, time.UTC)
	// CHEATING END

	// Gather data for the month
	sumMonth(&m0)

	// Gather metrics for the previous quarter
	// TODO - Do partial and last full or just last full or just the partial?
	fmt.Println("Gethering quarter metrics...")
	var q0 tfQuarter
	sumQuarter(&m0, &q0)

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
			fmt.Printf("    %v vuln count (crit/high/med/low): %v,%v,%v,%v\n", k, m0.bAppsCnt[k].crit, m0.bAppsCnt[k].high, m0.bAppsCnt[k].med, m0.bAppsCnt[k].low)
		}
	}
	// Worst apps
	fmt.Println("The worst apps of the month (and their score) are: (smaller is better)")
	sWorst := sortCounts(m0.worstApps, false)
	for j := 0; j < len(sWorst); j++ {
		for k, v := range sWorst[j] {
			fmt.Printf("  %v has a score of %v \n", k, v)
			fmt.Printf("    %v vuln count (crit/high/med/low): %v,%v,%v,%v\n", k, m0.wAppsCnt[k].crit, m0.wAppsCnt[k].high, m0.wAppsCnt[k].med, m0.wAppsCnt[k].low)
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
	// LoB stats
	fmt.Println("")
	fmt.Printf("Total number of assessments this month: %+v\n", m0.totAssess)
	fmt.Println("Assessments completed per LoB/Region")
	for k, v := range m0.assessByLob {
		fmt.Printf("  %+v had %+v assessments\n", k, v)
		fmt.Printf("    %v vuln count (crit/high/med/low): %v,%v,%v,%v\n", k, m0.vulnByLob[k].crit, m0.vulnByLob[k].high, m0.vulnByLob[k].med, m0.vulnByLob[k].low)
	}

	// ==========================[ Month - 1 ]=====================================

	// Current Month - 1 month
	var m1 tfMonth
	m1.tStamp = previousMonth(m0.tStamp)
	sumMonth(&m1)
	fmt.Println("")
	fmt.Println("==========[Month - 1 Metrics]==========")
	fmt.Printf("Metrics for %+v %+v", m1.tStamp.Month(), m1.tStamp.Year())
	fmt.Printf(", which is part of %+v\n", m1.quarter)
	fmt.Printf("Total vulnerabilities found for %+v was %+v\n", m1.tStamp.Month(), m1.totVulns)
	// Criticals
	if len(m1.critApps) > 0 {
		fmt.Printf("Total apps with critical findings is %+v\n", len(m1.critApps))
		fmt.Println("Individual App critical finding counts are:")
		sMCrit := sortCounts(m1.critApps, false)
		for j := 0; j < len(sMCrit); j++ {
			for k, v := range sMCrit[j] {
				fmt.Printf("  %v has %v critical findings\n", k, v)
			}
		}
		fmt.Printf("Percentage of Apps with critical findings is %.2f%%\n\n", m1.percntCrit)
	}
	// Highs
	if len(m1.highApps) > 0 {
		fmt.Printf("Total apps with highs is %+v\n", len(m1.highApps))
		fmt.Println("Individual App high finding counts are:")
		sMHigh := sortCounts(m1.highApps, false)
		for j := 0; j < len(sMHigh); j++ {
			for k, v := range sMHigh[j] {
				fmt.Printf("  %v has %v critical findings\n", k, v)
			}
		}
		fmt.Printf("Percentage of Apps with high findings is %.2f%%\n\n", m1.percntHigh)
	}
	// Best apps
	fmt.Println("The best apps of the month (and their score) are: (smaller is better)")
	sBest = sortCounts(m1.bestApps, true)
	for j := 0; j < len(sBest); j++ {
		for k, v := range sBest[j] {
			fmt.Printf("  %v has a score of %v \n", k, v)
			fmt.Printf("    %v vuln count (crit/high/med/low): %v,%v,%v,%v\n", k, m1.bAppsCnt[k].crit, m1.bAppsCnt[k].high, m1.bAppsCnt[k].med, m1.bAppsCnt[k].low)
		}
	}
	// Worst apps
	fmt.Println("The worst apps of the month (and their score) are: (smaller is better)")
	sWorst = sortCounts(m1.worstApps, false)
	for j := 0; j < len(sWorst); j++ {
		for k, v := range sWorst[j] {
			fmt.Printf("  %v has a score of %v \n", k, v)
			fmt.Printf("    %v vuln count (crit/high/med/low): %v,%v,%v,%v\n", k, m1.wAppsCnt[k].crit, m1.wAppsCnt[k].high, m1.wAppsCnt[k].med, m1.wAppsCnt[k].low)
		}
	}
	// Tool usage
	fmt.Printf("Number of assessments by type for %+v %+v\n", m1.tStamp.Month(), m1.tStamp.Year())
	sTools = sortCounts(m1.toolUsage, false)
	for j := 0; j < len(sTools); j++ {
		for k, v := range sTools[j] {
			fmt.Printf("  %v found %v results\n", k, v)
		}
	}
	// Top 10 CWEs
	fmt.Printf("The Top 10 CWE Vulnerabilities for %+v %+v\n", m1.tStamp.Month(), m1.tStamp.Year())
	sCwe = sortCounts(m1.topCWE, false)
	max = 10
	if len(sCwe) < max {
		max = len(sCwe)
	}
	for j := 0; j < max; j++ {
		for k, v := range sCwe[j] {
			fmt.Printf("  %v occurrences of %v\n", v, k)
		}
	}
	// LoB stats
	fmt.Println("")
	fmt.Printf("Total number of assessments this month: %+v\n", m1.totAssess)
	fmt.Println("Assessments completed per LoB/Region")
	for k, v := range m1.assessByLob {
		fmt.Printf("  %+v had %+v assessments\n", k, v)
		fmt.Printf("    %v vuln count (crit/high/med/low): %v,%v,%v,%v\n", k, m1.vulnByLob[k].crit, m1.vulnByLob[k].high, m1.vulnByLob[k].med, m1.vulnByLob[k].low)
	}

	// ==========================[ Month - 2 ]=====================================

	// Current Month - 2 months
	var m2 tfMonth
	m2.tStamp = previousMonth(m1.tStamp)
	sumMonth(&m2)
	fmt.Println("")
	fmt.Println("==========[Month - 2 Metrics]==========")
	fmt.Printf("Metrics for %+v %+v", m2.tStamp.Month(), m2.tStamp.Year())
	fmt.Printf(", which is part of %+v\n", m2.quarter)
	fmt.Printf("Total vulnerabilities found for %+v was %+v\n", m2.tStamp.Month(), m2.totVulns)
	// Criticals
	if len(m2.critApps) > 0 {
		fmt.Printf("Total apps with critical findings is %+v\n", len(m2.critApps))
		fmt.Println("Individual App critical finding counts are:")
		sMCrit := sortCounts(m2.critApps, false)
		for j := 0; j < len(sMCrit); j++ {
			for k, v := range sMCrit[j] {
				fmt.Printf("  %v has %v critical findings\n", k, v)
			}
		}
		fmt.Printf("Percentage of Apps with critical findings is %.2f%%\n\n", m2.percntCrit)
	}
	// Highs
	if len(m2.highApps) > 0 {
		fmt.Printf("Total apps with highs is %+v\n", len(m2.highApps))
		fmt.Println("Individual App high finding counts are:")
		sMHigh := sortCounts(m2.highApps, false)
		for j := 0; j < len(sMHigh); j++ {
			for k, v := range sMHigh[j] {
				fmt.Printf("  %v has %v critical findings\n", k, v)
			}
		}
		fmt.Printf("Percentage of Apps with high findings is %.2f%%\n\n", m2.percntHigh)
	}
	// Best apps
	fmt.Println("The best apps of the month (and their score) are: (smaller is better)")
	sBest = sortCounts(m2.bestApps, true)
	for j := 0; j < len(sBest); j++ {
		for k, v := range sBest[j] {
			fmt.Printf("  %v has a score of %v \n", k, v)
			fmt.Printf("    %v vuln count (crit/high/med/low): %v,%v,%v,%v\n", k, m2.bAppsCnt[k].crit, m2.bAppsCnt[k].high, m2.bAppsCnt[k].med, m2.bAppsCnt[k].low)
		}
	}
	// Worst apps
	fmt.Println("The worst apps of the month (and their score) are: (smaller is better)")
	sWorst = sortCounts(m2.worstApps, false)
	for j := 0; j < len(sWorst); j++ {
		for k, v := range sWorst[j] {
			fmt.Printf("  %v has a score of %v \n", k, v)
			fmt.Printf("    %v vuln count (crit/high/med/low): %v,%v,%v,%v\n", k, m2.wAppsCnt[k].crit, m2.wAppsCnt[k].high, m2.wAppsCnt[k].med, m2.wAppsCnt[k].low)
		}
	}
	// Tool usage
	fmt.Printf("Number of assessments by type for %+v %+v\n", m2.tStamp.Month(), m2.tStamp.Year())
	sTools = sortCounts(m2.toolUsage, false)
	for j := 0; j < len(sTools); j++ {
		for k, v := range sTools[j] {
			fmt.Printf("  %v found %v results\n", k, v)
		}
	}
	// Top 10 CWEs
	fmt.Printf("The Top 10 CWE Vulnerabilities for %+v %+v\n", m2.tStamp.Month(), m2.tStamp.Year())
	sCwe = sortCounts(m2.topCWE, false)
	max = 10
	if len(sCwe) < max {
		max = len(sCwe)
	}
	for j := 0; j < max; j++ {
		for k, v := range sCwe[j] {
			fmt.Printf("  %v occurrences of %v\n", v, k)
		}
	}
	// LoB stats
	fmt.Println("")
	fmt.Printf("Total number of assessments this month: %+v\n", m2.totAssess)
	fmt.Println("Assessments completed per LoB/Region")
	for k, v := range m2.assessByLob {
		fmt.Printf("  %+v had %+v assessments\n", k, v)
		fmt.Printf("    %v vuln count (crit/high/med/low): %v,%v,%v,%v\n", k, m2.vulnByLob[k].crit, m2.vulnByLob[k].high, m2.vulnByLob[k].med, m2.vulnByLob[k].low)
	}

	// ==========================[ Quarterly ]=====================================

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
				fmt.Printf("  %v has %v high findings\n", k, v)
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
	fmt.Println("Copy and Paste into a plain text file to create a CSV")
	fmt.Println("")
	fmt.Printf("Lob,%+v Crit/High,%+v Tot Asmts,%+v Crit/High,%+v Tot Asmts,%+v Crit/High,%+v Tot Asmts\n",
		m0.tStamp.Month(), m0.tStamp.Month(), m1.tStamp.Month(), m1.tStamp.Month(), m2.tStamp.Month(), m2.tStamp.Month())
	sAsByLob := sortCounts(m0.assessByLob, false)
	for j := 0; j < len(sAsByLob); j++ {
		for k, _ := range sAsByLob[j] {
			fmt.Printf("%+v,%+v,%+v,%+v,%+v,%+v,%+v\n", k,
				(m0.vulnByLob[k].crit + m0.vulnByLob[k].high), m0.assessByLob[k],
				(m1.vulnByLob[k].crit + m1.vulnByLob[k].high), m1.assessByLob[k],
				(m2.vulnByLob[k].crit + m2.vulnByLob[k].high), m2.assessByLob[k],
			)
		}
	}

	fmt.Println("")
	fmt.Println("Done.")

	//TODO - Global
	//(1) For LoB stats - First get a list of LoB/Teams (getTeams call),
	//    set them all to zero, _then_ run the month stat's like I do now so that
	//    those with no assessments still show up.
	// Add version and output it on each run start.
}
