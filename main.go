package main

import (
	"bufio"
	"fmt"
	"github.com/spf13/viper"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
	"github.com/tidwall/gjson"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Secret struct {
	SecretId  string
	SecretKey string
}

func LoadSecret() (string, string) {
	viper.SetConfigType("yaml")
	viper.SetConfigFile("secret.yaml")
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println(err.Error())
	}
	var Secrets Secret
	err = viper.Unmarshal(&Secrets)
	if err != nil {
		fmt.Println(err.Error())
	}
	SecretId := Secrets.SecretId
	SecretKey := Secrets.SecretKey
	return SecretId, SecretKey
}
func RandString(lenNum int) string { //获取随机字符串
	var chars = []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0"}
	str := strings.Builder{}
	length := len(chars)
	rand.Seed(time.Now().UnixNano()) //重新播种，否则值不会变
	for i := 0; i < lenNum; i++ {
		str.WriteString(chars[rand.Intn(length)])

	}
	return str.String()
}
func ApplyCert(Domain string) {
	SecretId, SecretKey := LoadSecret()
	credential := common.NewCredential(
		SecretId,
		SecretKey,
	)
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	client, _ := ssl.NewClient(credential, "", cpf)
	request := ssl.NewApplyCertificateRequest()
	request.DomainName = common.StringPtr(Domain)
	request.DvAuthMethod = common.StringPtr("DNS_AUTO")

	response, err := client.ApplyCertificate(request)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		fmt.Printf("An API error has returned: %s", err)
		return
	}
	if err != nil {
		panic(err)
	}
	res := gjson.Get(response.ToJsonString(), "Response")
	CertID := res.Get("CertificateId").String()

	byteContent := []byte(CertID)

	filename := time.Now().Format("2006-01-02") + "-CertID-" + RandString(2) + ".txt"
	err = os.WriteFile(filename, byteContent, 0644)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s", "证书申请成功")

}
func DownloadCert(CertID string) {
	SecretId, SecretKey := LoadSecret()
	credential := common.NewCredential(
		SecretId,
		SecretKey,
	)
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	// 实例化要请求产品的client对象,clientProfile是可选的
	client, _ := ssl.NewClient(credential, "", cpf)

	request := ssl.NewDescribeDownloadCertificateUrlRequest()
	request.CertificateId = common.StringPtr(CertID)
	request.ServiceType = common.StringPtr("nginx")

	response, err := client.DescribeDownloadCertificateUrl(request)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		fmt.Printf("An API error has returned: %s", err)
		return
	}
	if err != nil {
		panic(err)
	}
	res := gjson.Get(response.ToJsonString(), "Response")
	Downloadurl := res.Get("DownloadCertificateUrl").String()
	CertFilename := res.Get("DownloadFilename").String()
	saveDirectory := "./Certs"

	if err := downloadFile(Downloadurl, saveDirectory, CertFilename); err != nil {
		fmt.Printf("下载失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s", "下载完成，存储在当前文件夹下")
}

func showMenu() {
	fmt.Println("1. 申请证书")
	fmt.Println("2. 下载证书")
	fmt.Println("3. 自动部署")
	fmt.Print("请输入选项 (1/2/3) 或输入 exit 退出: ")
}
func downloadFile(url string, saveDir string, certFilename string) error {
	// 发送HTTP GET请求
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 检查HTTP状态码
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("服务器返回异常状态码: %d", resp.StatusCode)
	}

	// 从URL中提取文件名
	fileName := certFilename

	// 创建目标目录（如果不存在）
	if err := os.MkdirAll(saveDir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}

	// 创建目标文件
	filePath := filepath.Join(saveDir, fileName)
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	// 复制响应内容到文件
	written, err := io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("文件写入失败: %v", err)
	}

	fmt.Println("下载成功！\n文件路径: %s\n文件大小: %d bytes\n", filePath, written)
	return nil
}
func main() {
	reader := bufio.NewReader(os.Stdin)
	for {
		showMenu()
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		switch input {
		case "1":
			fmt.Print("请输入要申请证书的域名：")
			domain, _ := reader.ReadString('\n')
			domain = strings.TrimSpace(domain)
			ApplyCert(domain)
			return
		case "2":
			fmt.Print("请输入证书ID：")
			CertID, _ := reader.ReadString('\n')
			CertID = strings.TrimSpace(CertID)
			DownloadCert(CertID)
			return
		case "3":
			return
		case "exit":
			fmt.Println("\n感谢使用,再见！")
			return
		default:
			fmt.Println("\n❌ 无效输入，请重新选择")
		}
	}

}
