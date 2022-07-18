package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aksafarand/goprs/models"
	"github.com/dustin/go-humanize"
	cookiejar "github.com/juju/persistent-cookiejar"
)

type WriteCounter struct {
	Total uint64
}

func (wc *WriteCounter) Write(p []byte) (int, error) {
	n := len(p)
	wc.Total += uint64(n)
	wc.PrintProgress()
	return n, nil
}

func (wc WriteCounter) PrintProgress() {
	// Clear the line by using a character return to go back to the start and remove
	// the remaining characters by filling it with spaces
	fmt.Printf("\r%s", strings.Repeat(" ", 35))

	// Return again and print current status of download
	fmt.Printf("\rDownloading... %s complete", humanize.Bytes(wc.Total))
}

func printInfo(log *log.Logger) {
	log.Println("PRS Scheduler Report Downloader")
	log.Println("--------------------------------------------------------")
	log.Println("Kukuh Wikartomo - 2022")
	log.Println("kukuh.wikartomo@huawei.com")
	log.Println("--------------------------------------------------------")

}

func startProcess(log *log.Logger, confs ...*[]models.PrsCfg) error {

	for _, conf := range confs {
		for _, c := range *conf {
			rcName := c.RcName
			urlBase := c.Url

			usrpass := &models.UserPass{
				OrganizationName: "",
				Username:         c.UserName,
				Password:         c.UserPass,
				Multiregionname:  "",
			}

			// Setting HTTP Client for Each
			jar, _ := cookiejar.New(&cookiejar.Options{Filename: "./_storage/temp"})
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}

			client := &http.Client{
				Transport: tr, Jar: jar,
			}

			// getPubKey for Timestamp
			pubKey := getPubKey(client, urlBase)
			validateLogin, err := validateLogin(client, jar, urlBase, usrpass)
			if err != nil {
				log.Println(err)
				log.Println("!!! SKIP")
				break
			}

			log.Printf(">>> Connecting to %s with Username %s", rcName, c.UserName)

			input_url := validateLogin.RedirectURL
			u, err := url.Parse(input_url)
			if err != nil {
				log.Fatal(err)
			}

			queryParams := u.Query()
			serviceURL := queryParams["service"]
			ticketNo := queryParams["ticket"]

			if len(ticketNo[0]) > 0 {
				log.Println("Obtaining Ticket Number")
			} else {
				log.Println("!!! NO TICKET NUMBER RETURNED")
				break
			}

			LicenseLogin(client, jar, urlBase, serviceURL[0])

			var cm = make(map[string]int)
			for i, k := range jar.AllCookies() {
				cm[k.Name] = i
			}

			if _, ok := cm["bspsession"]; !ok {
				log.Println("!!! NO SESSION TOKEN RETURNED")
				break
			}

			log.Println("Obtaining Session Token")

			AuthService2(client, jar, urlBase, serviceURL[0], ticketNo[0])

			sessionLogin := GetTokenByTimestamp(client, jar, urlBase, pubKey.TimeStamp)

			getTask := &models.GetTask{
				Flag:       "performanceReport",
				SortType:   "nextExecTime",
				SortOrder:  "desc",
				CategoryID: 1,
				Page:       1,
				Rows:       10,
				SearchKey:  "",
				DirID:      -5,
				DirType:    4,
			}

			var taskMap = make(map[string]models.TaskDownload)
			for _, k := range c.JobName {
				var isNA bool
				isNA = false
				getTask.SearchKey = k
				taskDetail, _ := GetTaskID(client, urlBase, sessionLogin.CsrfToken, getTask)
				if len(taskDetail.Root) == 0 {
					isNA = true
					log.Printf("!!! NO TASK FOUND FOR %s", k)
				}

				if !isNA {
					taskResult := GetTaskResult(client, urlBase, taskDetail.Root[0].TaskID, sessionLogin.CsrfToken)
					fileName := taskResult.Root[0].Name
					loadId := taskDetail.Root[0].TaskID
					pathId := taskResult.Root[0].ResultID
					taskMap[k] = models.TaskDownload{
						FileName: fileName,
						LoadId:   loadId,
						PathId:   pathId,
					}
				}
			}

			for _, k := range c.JobName {
				getTask.SearchKey = k
				tm := taskMap[k]
				DownloadReport(client, urlBase, log, tm.FileName, getTask.Flag, tm.LoadId, tm.PathId)
			}

		}
	}

	return nil
}

func main() {

	logName := fmt.Sprintf("log_%s", time.Now().Format("20060102"))

	logFile, err := os.OpenFile("./_storage/"+logName+".log", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	log.SetOutput(logFile)

	log := log.New(io.MultiWriter(logFile, os.Stdout), "", log.Default().Flags())

	printInfo(log)

	// Loading Config
	var prsConf []models.PrsCfg

	jsonFile := "./prs_conf.json"
	c, err := ioutil.ReadFile(jsonFile)
	if err != nil {
		log.Fatal("Err In: Expected file prs_conf.json Only")

	}

	err = json.Unmarshal(c, &prsConf)
	if err != nil {
		log.Fatalf("Err In: %s\n", err.Error())
	}

	startProcess(log, &prsConf)

}

func getPubKey(client *http.Client, baseUrl string) *models.PubkeyResponse {

	urlLogin := url.URL{
		Scheme: "https",
		Host:   baseUrl,
		Path:   "unisso/pubkey",
	}

	urlRef := url.URL{
		Scheme:   "https",
		Host:     baseUrl,
		Path:     "/unisso/login.action",
		RawQuery: "decision=1&service=%2Funisess%2Fv1%2Fauth%3Fservice%3D%252Fossfacewebsite%252Findex.html%2523Home",
	}

	method := "GET"

	req, err := http.NewRequest(method, urlLogin.String(), nil)

	if err != nil {
		fmt.Println(err)
		return nil
	}
	req.Header.Add("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9,id;q=0.8,ms;q=0.7,fr;q=0.6")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("DNT", "1")
	req.Header.Add("Referer", urlRef.String())
	req.Header.Add("Sec-Fetch-Dest", "empty")
	req.Header.Add("Sec-Fetch-Mode", "cors")
	req.Header.Add("Sec-Fetch-Site", "same-origin")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.115 Safari/537.36")
	req.Header.Add("X-Requested-With", "XMLHttpRequest")
	req.Header.Add("sec-ch-ua", "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"102\", \"Google Chrome\";v=\"102\"")
	req.Header.Add("sec-ch-ua-mobile", "?0")
	req.Header.Add("sec-ch-ua-platform", "\"Windows\"")
	req.Header.Add("sec-gpc", "1")
	req.Header.Add("Cookie", "")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	var output models.PubkeyResponse
	json.Unmarshal(body, &output)

	return &output
}

func validateLogin(client *http.Client, jar *cookiejar.Jar, baseUrl string, usrpass *models.UserPass) (*models.ValidateLogin, error) {

	urlLogin := url.URL{
		Scheme:   "https",
		Host:     baseUrl,
		Path:     "unisso/v2/validateUser.action",
		RawQuery: "service=/unisess/v1/auth?service=%2Fossfacewebsite%2Findex.html&decision=1",
	}

	urlRef := url.URL{
		Scheme:   "https",
		Host:     baseUrl,
		Path:     "unisso/login.action",
		RawQuery: "decision=1&service=%2Funisess%2Fv1%2Fauth%3Fservice%3D%252Fossfacewebsite%252Findex.html%2523Home",
	}

	urlOrigin := url.URL{
		Scheme: "https",
		Host:   baseUrl,
	}

	method := "POST"

	usrpass_, err := json.Marshal(usrpass)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, urlLogin.String(), bytes.NewBuffer(usrpass_))

	if err != nil {

		return nil, err
	}
	req.Header.Add("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9,id;q=0.8,ms;q=0.7,fr;q=0.6")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("DNT", "1")
	req.Header.Add("Origin", urlOrigin.String())
	req.Header.Add("Referer", urlRef.String())
	req.Header.Add("Sec-Fetch-Dest", "empty")
	req.Header.Add("Sec-Fetch-Mode", "cors")
	req.Header.Add("Sec-Fetch-Site", "same-origin")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36")
	req.Header.Add("X-Requested-With", "XMLHttpRequest")
	req.Header.Add("sec-ch-ua", "\".Not/A)Brand\";v=\"99\", \"Google Chrome\";v=\"103\", \"Chromium\";v=\"103\"")
	req.Header.Add("sec-ch-ua-mobile", "?0")
	req.Header.Add("sec-ch-ua-platform", "\"Windows\"")
	req.Header.Add("sec-gpc", "1")

	res, err := client.Do(req)
	if err != nil {

		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {

		return nil, err
	}

	var output models.ValidateLogin
	json.Unmarshal(body, &output)

	if strings.Contains(output.ErrosMsg, "code") {
		return nil, fmt.Errorf("!!! CAPTCHA VERFICATION IS REQUIRED AT %s", baseUrl)
	}

	jar.Save()

	return &output, nil

}

func AuthService(client *http.Client, jar *cookiejar.Jar, serviceURL, ticketNo string) {

	url_, _ := url.Parse("https://10.70.16.40:31943/unisess/v1/auth")

	p1, _ := url.QueryUnescape(serviceURL)
	p2, _ := url.QueryUnescape(ticketNo)

	params := url.Values{}
	params.Add("service", p1)
	params.Add("ticket", p2)
	method := "GET"

	url_.RawQuery = params.Encode()

	req, err := http.NewRequest(method, url_.String(), nil)

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9,id;q=0.8,ms;q=0.7,fr;q=0.6")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("DNT", "1")
	req.Header.Add("Referer", "https://10.70.16.40:31943/unisso/login.action?service=%2Funisess%2Fv1%2Fauth%3Fservice%3D%252Fossfacewebsite%252Findex.html&decision=1")
	req.Header.Add("Sec-Fetch-Dest", "document")
	req.Header.Add("Sec-Fetch-Mode", "navigate")
	req.Header.Add("Sec-Fetch-Site", "same-origin")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36")
	req.Header.Add("sec-ch-ua", "\".Not/A)Brand\";v=\"99\", \"Google Chrome\";v=\"103\", \"Chromium\";v=\"103\"")
	req.Header.Add("sec-ch-ua-mobile", "?0")
	req.Header.Add("sec-ch-ua-platform", "\"Windows\"")
	req.Header.Add("sec-gpc", "1")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	jar.Save()

}

func AuthService2(client *http.Client, jar *cookiejar.Jar, baseUrl, serviceURL, ticketNo string) {

	urlLogin := url.URL{
		Scheme: "https",
		Host:   baseUrl,
		Path:   "unisess/v1/auth",
	}

	urlRef := url.URL{
		Scheme:   "https",
		Host:     baseUrl,
		Path:     "unisso/login.action",
		RawQuery: "service=%2Funisess%2Fv1%2Fauth%3Fservice%3D%252Fossfacewebsite%252Findex.html&decision=1",
	}

	p1, _ := url.QueryUnescape(serviceURL)
	p2, _ := url.QueryUnescape(ticketNo)

	params := url.Values{}
	params.Add("service", p1)
	params.Add("ticket", p2)
	method := "GET"

	urlLogin.RawQuery = params.Encode()

	req, err := http.NewRequest(method, urlLogin.String(), nil)

	if err != nil {
		return
	}
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9,id;q=0.8,ms;q=0.7,fr;q=0.6")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("DNT", "1")
	req.Header.Add("Referer", urlRef.String())
	req.Header.Add("Sec-Fetch-Dest", "document")
	req.Header.Add("Sec-Fetch-Mode", "navigate")
	req.Header.Add("Sec-Fetch-Site", "same-origin")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36")
	req.Header.Add("sec-ch-ua", "\".Not/A)Brand\";v=\"99\", \"Google Chrome\";v=\"103\", \"Chromium\";v=\"103\"")
	req.Header.Add("sec-ch-ua-mobile", "?0")
	req.Header.Add("sec-ch-ua-platform", "\"Windows\"")
	req.Header.Add("sec-gpc", "1")

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	jar.Save()

}

func LicenseLogin(client *http.Client, jar *cookiejar.Jar, baseUrl, serviceURL string) {

	urlLogin := url.URL{
		Scheme: "https",
		Host:   baseUrl,
		Path:   "plat/licapp/v1/licenselogin",
	}

	p1, _ := url.QueryUnescape(serviceURL)

	params := url.Values{}
	params.Add("service", p1)
	method := "GET"

	urlLogin.RawQuery = params.Encode()

	urlRef := url.URL{
		Scheme:   "https",
		Host:     baseUrl,
		Path:     "unisso/login.action",
		RawQuery: "service=%2Funisess%2Fv1%2Fauth%3Fservice%3D%252Fossfacewebsite%252Findex.html&decision=1",
	}

	req, err := http.NewRequest(method, urlLogin.String(), nil)

	if err != nil {
		return
	}
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9,id;q=0.8,ms;q=0.7,fr;q=0.6")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Cookie", "locale=en-us")
	req.Header.Add("DNT", "1")
	req.Header.Add("Referer", urlRef.String())
	req.Header.Add("Sec-Fetch-Dest", "document")
	req.Header.Add("Sec-Fetch-Mode", "navigate")
	req.Header.Add("Sec-Fetch-Site", "same-origin")
	req.Header.Add("Sec-Fetch-User", "?1")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36")
	req.Header.Add("sec-ch-ua", "\".Not/A)Brand\";v=\"99\", \"Google Chrome\";v=\"103\", \"Chromium\";v=\"103\"")
	req.Header.Add("sec-ch-ua-mobile", "?0")
	req.Header.Add("sec-ch-ua-platform", "\"Windows\"")
	req.Header.Add("sec-gpc", "1")

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	jar.Save()

}

func GetTokenByTimestamp(client *http.Client, jar *cookiejar.Jar, baseUrl string, timeStamp int) *models.SessionLogin {

	ts := strconv.Itoa(timeStamp)

	urlLogin := url.URL{
		Scheme: "https",
		Host:   baseUrl,
		Path:   "unisess/v1/auth/session",
	}

	params := url.Values{}
	params.Add("_", ts)
	method := "GET"

	urlLogin.RawQuery = params.Encode()

	urlRef := url.URL{
		Scheme: "https",
		Host:   baseUrl,
		Path:   "evacronwebsite/assets/htmls/scheduled-report.html",
	}

	req, err := http.NewRequest(method, urlLogin.String(), nil)

	if err != nil {
		fmt.Println(err)
		return nil
	}
	req.Header.Add("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9,id;q=0.8,ms;q=0.7,fr;q=0.6")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("DNT", "1")
	req.Header.Add("Referer", urlRef.String())
	req.Header.Add("Sec-Fetch-Dest", "empty")
	req.Header.Add("Sec-Fetch-Mode", "cors")
	req.Header.Add("Sec-Fetch-Site", "same-origin")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36")
	req.Header.Add("X-Requested-With", "XMLHttpRequest")
	req.Header.Add("sec-ch-ua", "\".Not/A)Brand\";v=\"99\", \"Google Chrome\";v=\"103\", \"Chromium\";v=\"103\"")
	req.Header.Add("sec-ch-ua-mobile", "?0")
	req.Header.Add("sec-ch-ua-platform", "\"Windows\"")
	req.Header.Add("sec-gpc", "1")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	var output models.SessionLogin
	json.Unmarshal(body, &output)

	return &output
}

func GetTaskID(client *http.Client, baseUrl, token string, taskRequest *models.GetTask) (*models.TaskDetail, error) {

	urlLogin := url.URL{
		Scheme: "https",
		Host:   baseUrl,
		Path:   "rest/prs/scheduletask/scheduled-report/get-task",
	}

	method := "POST"

	taskRequest_, err := json.Marshal(taskRequest)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, urlLogin.String(), bytes.NewBuffer(taskRequest_))

	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	req.Header.Add("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9,id;q=0.8,ms;q=0.7,fr;q=0.6")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("DNT", "1")
	req.Header.Add("Sec-Fetch-Dest", "empty")
	req.Header.Add("Sec-Fetch-Mode", "cors")
	req.Header.Add("Sec-Fetch-Site", "same-origin")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36")
	req.Header.Add("X-Requested-With", "XMLHttpRequest")
	req.Header.Add("roarand", token)
	req.Header.Add("sec-ch-ua", "\".Not/A)Brand\";v=\"99\", \"Google Chrome\";v=\"103\", \"Chromium\";v=\"103\"")
	req.Header.Add("sec-ch-ua-mobile", "?0")
	req.Header.Add("sec-ch-ua-platform", "\"Windows\"")
	req.Header.Add("sec-gpc", "1")

	res, err := client.Do(req)
	if err != nil {

		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {

		return nil, err
	}

	var output models.TaskDetail
	json.Unmarshal(body, &output)

	return &output, nil
}

func DownloadReport(client *http.Client, baseUrl string, log *log.Logger, fileName, taskType string, loadId, path int) {

	urlLogin := url.URL{
		Scheme: "https",
		Host:   baseUrl,
		Path:   "rest/prs/scheduletask/scheduletask-report/download-browse-file",
	}

	urlRef := url.URL{
		Scheme: "https",
		Host:   baseUrl,
		Path:   "evacronwebsite/assets/htmls/scheduled-report.html",
	}

	params := url.Values{}
	params.Add("fileName", fileName)
	params.Add("taskType", taskType)
	params.Add("loadId", strconv.Itoa(loadId))
	params.Add("path", strconv.Itoa(path))
	params.Add("userAgent", "MSIE")

	method := "GET"
	urlLogin.RawQuery = params.Encode()

	req, err := http.NewRequest(method, urlLogin.String(), nil)

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9,id;q=0.8,ms;q=0.7,fr;q=0.6")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("DNT", "1")
	req.Header.Add("Referer", urlRef.String())
	req.Header.Add("Sec-Fetch-Dest", "iframe")
	req.Header.Add("Sec-Fetch-Mode", "navigate")
	req.Header.Add("Sec-Fetch-Site", "same-origin")
	req.Header.Add("Sec-Fetch-User", "?1")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36")
	req.Header.Add("sec-ch-ua", "\".Not/A)Brand\";v=\"99\", \"Google Chrome\";v=\"103\", \"Chromium\";v=\"103\"")
	req.Header.Add("sec-ch-ua-mobile", "?0")
	req.Header.Add("sec-ch-ua-platform", "\"Windows\"")
	req.Header.Add("sec-gpc", "1")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	out, err := os.Create("./_files/" + strings.ReplaceAll(fileName, `"`, ""))
	if err != nil {
		return
	}
	defer out.Close()

	counter := &WriteCounter{}

	log.Println("Fetch", fileName)
	if _, err = io.Copy(out, io.TeeReader(res.Body, counter)); err != nil {
		out.Close()
		log.Println("FAILED Download", fileName)
		return
	}
	fmt.Print("\n")

}

func GetTaskResult(client *http.Client, baseUrl string, taskId int, token string) *models.TaskResult {

	urlLogin := url.URL{
		Scheme: "https",
		Host:   baseUrl,
		Path:   "rest/prs/scheduletask/scheduled-report/get-taskLog-by-taskid-web",
	}

	urlRef := url.URL{
		Scheme: "https",
		Host:   baseUrl,
		Path:   "evacronwebsite/assets/htmls/scheduled-report.html",
	}

	urlOrigin := url.URL{
		Scheme: "https",
		Host:   baseUrl,
	}

	method := "POST"

	taskRequest := &models.TaskRequest{
		Flag:      "performanceReport",
		SortType:  "endTime",
		SortOrder: "desc",
		Rows:      10,
		Page:      1,
		TaskID:    taskId,
	}

	tr, err := json.Marshal(taskRequest)
	if err != nil {
		fmt.Printf("Error: %s", err)
		return nil
	}

	payload := strings.NewReader(string(tr))

	req, err := http.NewRequest(method, urlLogin.String(), payload)

	if err != nil {
		fmt.Println(err)
		return nil
	}
	req.Header.Add("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9,id;q=0.8,ms;q=0.7,fr;q=0.6")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("DNT", "1")
	req.Header.Add("Origin", urlOrigin.String())
	req.Header.Add("Referer", urlRef.String())
	req.Header.Add("Sec-Fetch-Dest", "empty")
	req.Header.Add("Sec-Fetch-Mode", "cors")
	req.Header.Add("Sec-Fetch-Site", "same-origin")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36")
	req.Header.Add("X-Requested-With", "XMLHttpRequest")
	req.Header.Add("roarand", token)
	req.Header.Add("sec-ch-ua", "\".Not/A)Brand\";v=\"99\", \"Google Chrome\";v=\"103\", \"Chromium\";v=\"103\"")
	req.Header.Add("sec-ch-ua-mobile", "?0")
	req.Header.Add("sec-ch-ua-platform", "\"Windows\"")
	req.Header.Add("sec-gpc", "1")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	var output models.TaskResult
	json.Unmarshal(body, &output)

	return &output
}
