package main

import (
	"boot/util"
	"fmt"
	"github.com/urfave/cli"
	"log"
	"os"
	"strings"
)

func initFIle(name, path, opath, v string) {

	//pom
	createFile(util.Pom(name, v, opath))
	//application
	createFile(util.ApplicationApp(name, path, opath))
	//test
	createFile(util.TestFile(name, path, opath))
	//resources
	createFile(util.LogbackSpring(name))
	createFile(util.Application(name))
	createFile(util.ApplicationDev(name))
	createFile(util.ApplicationProd(name))
	createFile(util.MybatisConfig(name))
	createFile(util.UserMapper(name))
	//module
	createFile(util.TestController(name, path, opath))
	createFile(util.TestService(name, path, opath))
	//config
	createFile(util.Author(name, path, opath))
	createFile(util.Decrypt(name, path, opath))
	createFile(util.Encrypt(name, path, opath))
	createFile(util.SecurityPermission(name, path, opath))
	createFile(util.AuthorityType(name, path, opath))

	createFile(util.EncryptResponseBodyAdvice(name, path, opath))
	createFile(util.EncryptRequestBodyAdvice(name, path, opath))

	createFile(util.AuthorAspect(name, path, opath))
	createFile(util.CustomCorsConfiguration(name, path, opath))
	createFile(util.Http2Config(name, path, opath))
	createFile(util.AuthorizationInterceptor(name, path, opath))
	createFile(util.SecurityInterceptor(name, path, opath))
	createFile(util.WebAppConfigurer(name, path, opath))
	createFile(util.JsonConfig(name, path, opath))
	createFile(util.SecurityContextHolder(name, path, opath))
	createFile(util.JWTToken(name, path, opath))
	createFile(util.AppInit(name, path, opath))
	//bean
	createFile(util.Config(name, path, opath))
	createFile(util.Result(name, path, opath))
	createFile(util.Tips(name, path, opath))
	createFile(util.UserMapperA(name, path, opath))
	createFile(util.User(name, path, opath))
	createFile(util.Authority(name, path, opath))
	createFile(util.Role(name, path, opath))
	createFile(util.UserRepository(name, path, opath))
	createFile(util.RoleRepository(name, path, opath))
	createFile(util.AuthorityRepository(name, path, opath))
	//util
	createFile(util.PasswordEncoderUtils(name, path, opath))
	createFile(util.FileUtils(name, path, opath))
	createFile(util.PathUtils(name, path, opath))
	createFile(util.AesEncryptUtils(name, path, opath))
	createFile(util.IOUtils(name, path, opath))
	createFile(util.StringBuilderWriter(name, path, opath))
}

func createFile(path, content string) {
	//文件的创建，Create会根据传入的文件名创建文件，默认权限是0666
	fileObj, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Println("Failed to open the file", err.Error())
		os.Exit(2)
	}
	defer fileObj.Close()
	if _, err := fileObj.WriteString(content); err == nil {
		//fmt.Println("Successful writing to the file with os.OpenFile and *File.WriteString method.",content)
	}
}

func getDir(path string) string {
	paths := strings.Split(path, ".")
	packageName := ""
	for _, p := range paths {
		packageName = packageName + "/" + p
	}
	return packageName
}

func createDir(path string) {
	//创建多级目录和设置权限
	os.MkdirAll(path, 0777)
}

func dirInit(pn, p string) {
	mp := pn + "/src/main"
	tp := pn + "/src/test/java"
	rp := mp + "/resources"
	jp := mp + "/java"
	//main

	//java

	//common
	createDir(jp + "/" + p + "/common/bean")
	createDir(jp + "/" + p + "/common/mapper")
	createDir(jp + "/" + p + "/common/pojo")
	createDir(jp + "/" + p + "/common/repository")
	createDir(jp + "/" + p + "/common/util")
	//config
	createDir(jp + "/" + p + "/config/annotation")
	createDir(jp + "/" + p + "/config/aop")
	createDir(jp + "/" + p + "/config/cors")
	createDir(jp + "/" + p + "/config/http2")
	createDir(jp + "/" + p + "/config/interceptor")
	createDir(jp + "/" + p + "/config/json")
	createDir(jp + "/" + p + "/config/mvc")
	createDir(jp + "/" + p + "/config/security")
	createDir(jp + "/" + p + "/config/token")
	createDir(jp + "/" + p + "/config/init")
	createDir(jp + "/" + p + "/config/advice")
	//module
	createDir(jp + "/" + p + "/module/test")
	createDir(jp + "/" + p + "/module/user")

	//resources
	createDir(rp + "/config")
	createDir(rp + "/mybatis/mapper")
	createDir(rp + "/static")
	//test
	createDir(tp + "/" + p)

}

func main() {

	//实例化一个命令行程序
	app := cli.NewApp()
	//程序名称
	app.Name = "boot"
	//程序的用途描述
	app.Usage = "脚手架"
	//程序的版本号
	app.Version = "1.0.0"

	//预置变量

	var projectName string
	var packageName string
	var springBootVersion string

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "project, n",
			Value:       "boot",
			Usage:       "项目名",
			Destination: &projectName,
		},
		cli.StringFlag{
			Name:        "package, p",
			Value:       "com.snow.boot",
			Usage:       "包名",
			Destination: &packageName,
		},
		cli.StringFlag{
			Name:        "springboot, s",
			Value:       "2.1.0.RELEASE",
			Usage:       "springboot 版本号",
			Destination: &springBootVersion,
		},
	}
	app.Commands = []cli.Command{
		{
			Name:    "init",
			Aliases: []string{"i"},
			Usage:   "项目初始化",
			Action: func(c *cli.Context) error {
				path := getDir(packageName)
				dirInit(projectName, path)
				initFIle(projectName, path, packageName, springBootVersion)
				fmt.Println("项目初始化成功")
				return nil
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}
