// metrics-structs.go
// data structuctures for metrics from the ThreadFix REST API
package main

import (
	"net/http"
	"time"
)

// Data structures to handle metrics from ThreadFix API as documented at
// https://github.com/denimgroup/threadfix/wiki/Threadfix-REST-Interface
// These will gather metrics by month for quarter and yearly roll-ups

///////////////////////////////////////////////////////////////////
// Struct for metrics gathered per month from the Vul Search API //
///////////////////////////////////////////////////////////////////

type tfMonth struct {
	tStamp     time.Time      // Time stored as Go's time.Time stored as first day of the month
	mpartial   bool           // if we're part way through the month
	quarter    string         // what quarter we're in - e.g. 2015-Q1
	qpartial   bool           // if we're part way through the quarter
	totVulns   int            // total vuls - includes all but info
	critApps   map[string]int // map of [app name] count of crits
	percntCrit float64        // apps with crits / total apps * 100 e.g. 8.03%
	highApps   map[string]int // map of [app name] count of highs
	percntHigh float64        // apps with highs / total apps * 100 e.g. 23.72%
	// maps of [app name] vuln score for the next 2
	bestApps      map[string]int // top 10 apps with least vuln score
	worstApps     map[string]int // top 10 apps with the greatest vuln score
	toolUsage     map[string]int // map of [tool name] / count of usage
	topCWE        map[int]int    // top 10 CWEs in this month's findings
	trackerCount  map[string]int // map of [app name] issue tracker count
	percntTracker float64        // apps with issue tracker / total apps
}

/////////////////////////////////////////////////////////////////////
// Struct for metrics gathered per quarter from the Vul Search API //
/////////////////////////////////////////////////////////////////////

type tfQuarter struct {
	qLabel     string         // what quarter we're in - e.g. 2015-Q1
	qTStamps   [3]time.Time   // array of Time from Go's time pacakge
	months     [3]*tfMonth    // pointers to the three months that make up the quarter
	critApps   map[string]int // map of [app name] count of crits
	percntCrit float64        // apps with crits / total apps * 100 e.g. 8.03%
	highApps   map[string]int // map of [app name] count of highs
	percntHigh float64        // apps with highs / total apps * 100 e.g. 23.72%
	// maps of [app name] vuln score for the next 2
	bestApps      map[string]int // top 10 apps with least vuln score
	worstApps     map[string]int // top 10 apps with the greatest vuln score
	toolUsage     map[string]int // map of [tool name] / count of usage
	topCWE        map[int]int    // top 10 CWEs in this month's findings
	trackerCount  map[string]int // map of [app name] issue tracker count
	percntTracker float64        // apps with issue tracker / total apps
}

//////////////////////////////////////////////////////////////////
// Struct for metrics gathered per year from the Vul Search API //
//////////////////////////////////////////////////////////////////

type tfYear struct {
	year       int            // Current year
	yearEnds   string         // quarter in which the year ends - year = 4 quarters not calendar year
	qLabels    [4]string      // array of quarter lables e.g. 2015-Q1
	quarters   [4]*tfQuarter  // pointers to the 4 quarters that make up the past year
	critApps   map[string]int // map of [app name] count of crits
	percntCrit float64        // apps with crits / total apps * 100 e.g. 8.03%
	highApps   map[string]int // map of [app name] count of highs
	percntHigh float64        // apps with highs / total apps * 100 e.g. 23.72%
	// maps of [app name] vuln score for the next 2
	bestApps      map[string]int // top 10 apps with least vuln score
	worstApps     map[string]int // top 10 apps with the greatest vuln score
	toolUsage     map[string]int // map of [tool name] / count of usage
	topCWE        map[int]int    // top 10 CWEs in this month's findings
	trackerCount  map[string]int // map of [app name] issue tracker count
	percntTracker float64        // apps with issue tracker / total apps
}

////////////////////////////////////////
// Helper data structures for metrics //
////////////////////////////////////////

// TF Client
var tfc *http.Client = nil

// Summary data structures
var appCount int = 0
var teamCounts = make(map[string]int)
var critApps = make(map[string]int)

type quarter struct {
	label string
	month [3]time.Month
	year  int
}

// Define how we want to do quarters of a year
var qtrDefs = map[int]string{
	1:  "Q1",
	2:  "Q1",
	3:  "Q1",
	4:  "Q2",
	5:  "Q2",
	6:  "Q2",
	7:  "Q3",
	8:  "Q3",
	9:  "Q3",
	10: "Q4",
	11: "Q4",
	12: "Q4",
}

// And the months the quarters end on
var quarterEnd = map[int]int{
	1: 3,
	2: 6,
	3: 9,
	4: 12,
}
