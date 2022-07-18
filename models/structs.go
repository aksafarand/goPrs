package models

type PubkeyResponse struct {
	Version       string `json:"version"`
	PubKey        string `json:"pubKey"`
	TimeStamp     int    `json:"timeStamp"`
	EnableEncrypt bool   `json:"enableEncrypt"`
}

type UserPass struct {
	OrganizationName string `json:"organizationName"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	Multiregionname  string `json:"multiRegionName"`
}

type ValidateLogin struct {
	ErrorCode           string `json:"errorCode"`
	ErrosMsg            string `json:"errorMsg"`
	RedirectURL         string `json:"redirectURL"`
	RespMultiRegionName string `json:"respMultiRegionName"`
	TwoFactorStatus     string `json:"twoFactorStatus"`
	VerifyCodeCreate    bool   `json:"verifyCodeCreate"`
}

type SessionLogin struct {
	CsrfToken string      `json:"csrfToken"`
	Locale    interface{} `json:"locale"`
	User      struct {
		ID     string      `json:"id"`
		Name   string      `json:"name"`
		Domain interface{} `json:"domain"`
		Ops    []string    `json:"ops"`
	} `json:"user"`
	Project struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"project"`
	Domain interface{} `json:"domain"`
	Roles  []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"roles"`
	UserRoles interface{} `json:"userRoles"`
	Xlinks    struct {
		Logout       string      `json:"logout"`
		AssumeAgency interface{} `json:"assumeAgency"`
	} `json:"xlinks"`
	ODomain struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"oDomain"`
	ClientID      string      `json:"clientId"`
	SessionExtend interface{} `json:"sessionExtend"`
}

type TaskDetail struct {
	Rows         int `json:"rows"`
	TotalPages   int `json:"totalPages"`
	CurPage      int `json:"curPage"`
	TotalRecords int `json:"totalRecords"`
	Root         []struct {
		State                 int    `json:"state"`
		PeriodType            int    `json:"periodType"`
		TaskType              int    `json:"taskType"`
		RunnedTimes           int    `json:"runnedTimes"`
		TaskID                int    `json:"taskId"`
		ReportID              int    `json:"reportId"`
		TaskName              string `json:"taskName"`
		ReportName            string `json:"reportName"`
		ReportPath            string `json:"reportPath"`
		Creator               string `json:"creator"`
		Original_PreExecTime  string `json:"original_preExecTime"`
		PreExecTime           string `json:"preExecTime"`
		Original_NextExecTime string `json:"original_nextExecTime"`
		NextExecTime          string `json:"nextExecTime"`
		IsWrite               string `json:"isWrite"`
		ExecPeriod            int    `json:"execPeriod"`
		PreExcuDuration       int    `json:"preExcuDuration"`
		OriginalPreExecTime   string `json:"originalPreExecTime"`
		OriginalNextExecTime  string `json:"originalNextExecTime"`
	} `json:"root"`
}

type TaskRequest struct {
	Flag      string `json:"flag"`
	SortType  string `json:"sortType"`
	SortOrder string `json:"sortOrder"`
	Rows      int    `json:"rows"`
	Page      int    `json:"page"`
	TaskID    int    `json:"taskId"`
}

type GetTask struct {
	Flag       string `json:"flag"`
	SortType   string `json:"sortType"`
	SortOrder  string `json:"sortOrder"`
	CategoryID int    `json:"categoryId"`
	Page       int    `json:"page"`
	Rows       int    `json:"rows"`
	SearchKey  string `json:"searchKey"`
	DirID      int    `json:"dirId"`
	DirType    int    `json:"dirType"`
}

type TaskDownload struct {
	FileName string
	LoadId   int
	PathId   int
}

type TaskResult struct {
	Rows         int `json:"rows"`
	TotalPages   int `json:"totalPages"`
	CurPage      int `json:"curPage"`
	TotalRecords int `json:"totalRecords"`
	Root         []struct {
		TaskID                int    `json:"taskId"`
		ResultID              int    `json:"resultId"`
		MenuID                int    `json:"menuId"`
		TaskName              string `json:"taskName"`
		ReportName            string `json:"reportName"`
		Path                  string `json:"path"`
		Name                  string `json:"name"`
		Original_BeginTime    string `json:"original_beginTime"`
		BeginTime             string `json:"beginTime"`
		Original_EndTime      string `json:"original_endTime"`
		EndTime               string `json:"endTime"`
		Original_GenerateTime string `json:"original_generateTime"`
		GenerateTime          string `json:"generateTime"`
		Size                  int    `json:"size"`
		State                 string `json:"state"`
		DetailList            string `json:"detailList"`
		WebBrowse             bool   `json:"webBrowse"`
		GenFile               bool   `json:"genFile"`
		BaseTime              string `json:"baseTime"`
		Original_BaseTime     string `json:"original_baseTime"`
		ExecDuration          int    `json:"execDuration"`
		OriginalBaseTime      string `json:"originalBaseTime"`
		OriginalGenerateTime  string `json:"originalGenerateTime"`
		OriginalEndTime       string `json:"originalEndTime"`
		OriginalBeginTime     string `json:"originalBeginTime"`
	} `json:"root"`
}

type PrsCfg struct {
	RcName   string   `json:"rcName"`
	Url      string   `json:"url"`
	UserName string   `json:"userName"`
	UserPass string   `json:"userPass"`
	JobName  []string `json:"jobName"`
}
