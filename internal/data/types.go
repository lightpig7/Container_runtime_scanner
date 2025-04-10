package data

// Container vulnerability information

type ContainerVulnerability struct {
	CVEId            string   `json:"cveId"`
	Technology       string   `json:"technology"`
	AffectedVersions []string `json:"affectedVersions"`
	CVSSScore        float64  `json:"cvssScore"`
	Severity         string   `json:"severity"`
}

// CVE data structures (matching NVD JSON format)
type CVE struct {
	CVEDataType         string    `json:"dataType"`
	CVEDataFormat       string    `json:"dataFormat"`
	CVEDataVersion      string    `json:"dataVersion"`
	CVEDataNumberOfCVEs string    `json:"numberOfCVEs"`
	CVEDataTimestamp    string    `json:"timestamp"`
	CVEItems            []CVEItem `json:"CVE_Items"`
}

type CVEItem struct {
	CVE struct {
		CVEDataMeta struct {
			ID string `json:"ID"`
		} `json:"CVE_data_meta"`
		Description struct {
			DescriptionData []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"description_data"`
		} `json:"description"`
	} `json:"cve"`
	Configurations struct {
		Nodes []struct {
			Operator string `json:"operator"`
			CpeMatch []struct {
				Vulnerable bool   `json:"vulnerable"`
				Cpe23Uri   string `json:"cpe23Uri"`
			} `json:"cpe_match,omitempty"`
			Children []struct {
				Operator string `json:"operator"`
				CpeMatch []struct {
					Vulnerable bool   `json:"vulnerable"`
					Cpe23Uri   string `json:"cpe23Uri"`
				} `json:"cpe_match,omitempty"`
			} `json:"children,omitempty"`
		} `json:"nodes"`
	} `json:"configurations"`
	Impact struct {
		BaseMetricV3 struct {
			CVSSV3 struct {
				Version               string  `json:"version"`
				VectorString          string  `json:"vectorString"`
				AttackVector          string  `json:"attackVector"`
				AttackComplexity      string  `json:"attackComplexity"`
				PrivilegesRequired    string  `json:"privilegesRequired"`
				UserInteraction       string  `json:"userInteraction"`
				Scope                 string  `json:"scope"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
				BaseSeverity          string  `json:"baseSeverity"`
			} `json:"cvssV3"`
		} `json:"baseMetricV3,omitempty"`
		BaseMetricV2 struct {
			CVSSV2 struct {
				Version               string  `json:"version"`
				VectorString          string  `json:"vectorString"`
				AccessVector          string  `json:"accessVector"`
				AccessComplexity      string  `json:"accessComplexity"`
				Authentication        string  `json:"authentication"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
			} `json:"cvssV2"`
			Severity string `json:"severity"`
		} `json:"baseMetricV2,omitempty"`
	} `json:"impact"`
	PublishedDate    string `json:"publishedDate"`
	LastModifiedDate string `json:"lastModifiedDate"`
}

// Map of container technologies and their aliases
var containerTechnologies = map[string][]string{
	"docker":     {"docker", "moby", "docker-engine"},
	"containerd": {"containerd"},
	"runc":       {"runc"},
	"kubernetes": {"kubernetes", "k8s"},
	"podman":     {"podman"},
	"cri-o":      {"cri-o", "crio"},
	"buildah":    {"buildah"},
	"skopeo":     {"skopeo"},
}
