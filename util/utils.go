package util

import "fmt"

func TestService(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/module/test/TestService.java", `package ` + opn + `.module.test;

import ` + opn + `.common.bean.Config;
import ` + opn + `.common.bean.Result;
import ` + opn + `.common.bean.Tips;
import ` + opn + `.common.util.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


@Service
public class TestService {

    @Autowired
    private FileUtils fileUtils;
    @Autowired
    private Config config;

    /**不支持的-文件类型*/
    private static List<String> falseType=new ArrayList<>();



    public Result uploadFile(MultipartFile file) {
      if (checkType(getType(file)))return Result.fail(Tips.TYPE_FALSE.msg);
      String path=fileUtils.saveFile(Paths.get(config.getFilePath()),file);
      if (path==null)return Result.fail();
      String url="https://"+config.getFileHost()+":"+config.getFilePort()+"/"+config.getFileUrl()+"/"+path;
      return Result.success(url,path);
    }


    /**判断该类型是否支持上传*/
    private boolean checkType(String type){
        if (falseType.size()==0)initType();
        return falseType.contains(type);
    }

    /**类型初始化*/
    private void initType(){
        String[] strings=config.getFileType().split(",");
        Arrays.stream(strings).forEach(i->falseType.add(i));
    }



    /**获取文件类型*/
    private String getType(MultipartFile file){
        String fileName = file.getOriginalFilename();
        //获取文件类型
        String suffix = fileName.substring(fileName.lastIndexOf(".") + 1);
        return suffix;
    }


    public Result path() {
        return Result.success("https://"+config.getFileHost()+":"+config.getFilePort()+"/"+config.getFileUrl()+"/");
    }
}

`
}

func TestController(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/module/test/TestController.java", `package ` + opn + `.module.test;

import ` + opn + `.common.bean.Result;
import ` + opn + `.common.pojo.Authority;
import ` + opn + `.common.pojo.Role;
import ` + opn + `.common.pojo.User;
import ` + opn + `.common.repository.AuthorityRepository;
import ` + opn + `.common.repository.RoleRepository;
import ` + opn + `.common.repository.UserRepository;
import ` + opn + `.config.annotation.Decrypt;
import ` + opn + `.config.annotation.Encrypt;
import ` + opn + `.config.annotation.SecurityPermission;
import ` + opn + `.config.token.JWTToken;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Api(tags = "测试")
@RestController
@RequestMapping("test")
public class TestController {

    @Autowired
    private TestService testService;
    @Autowired
    private JWTToken jwtToken;
    @Autowired
    private AuthorityRepository authorityRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private UserRepository userRepository;




    @GetMapping("sexs")
    @Encrypt
    public Result sexs(){
        return Result.success("好");
    }

    @PostMapping("usersx")
    @Decrypt
    public Result usersx(@RequestBody Result result){
        return result;
    }


    @PostMapping("usersx2")
    @Decrypt
    @Encrypt
    public Result usersx2(@RequestBody Result result){
        return result;
    }

    @GetMapping("users")
    public ResponseEntity users(){

        List<User> users=userRepository.findAll();
        users.forEach(k->{
            k.setToken(jwtToken.createToken(    String.valueOf(k.getId())));
        });

        return ResponseEntity.ok(users);
    }

    @PostMapping("userReduceRole")
    public ResponseEntity userReduceRole(@RequestParam Long userId,
                                         @RequestParam Long roleId){
        Optional<Role> o=roleRepository.findById(roleId);
        if (!o.isPresent())return ResponseEntity.notFound().build();
        Optional<User> r=userRepository.findById(userId);
        if (!r.isPresent())return ResponseEntity.notFound().build();
        User user=r.get();
        List<Role> roles=user.getRoles();
        roles.remove(o.get());
        return ResponseEntity.ok(userRepository.save(user));
    }

    @PostMapping("userAddRole")
    public ResponseEntity userAddRole(@RequestParam Long userId,
                                      @RequestParam Long roleId){
        Optional<Role> o=roleRepository.findById(roleId);
        if (!o.isPresent())return ResponseEntity.notFound().build();
        Optional<User> r=userRepository.findById(userId);
        if (!r.isPresent())return ResponseEntity.notFound().build();

        User user=r.get();
        List<Role> roles=user.getRoles();
        roles.add(o.get());
        user.setRoles(roles);
        return ResponseEntity.ok(userRepository.save(user));
    }

    @PostMapping("addUser")
    public ResponseEntity addUser(@RequestParam Long roleId,
                                  @RequestParam String name){
        Optional<Role> o=roleRepository.findById(roleId);
        if (!o.isPresent())return ResponseEntity.notFound().build();
        return ResponseEntity.ok(userRepository.save(User.builder().username(name).build()));
    }


    @GetMapping("roles")
    public ResponseEntity roles(){
        return ResponseEntity.ok(roleRepository.findAll());
    }

    @PostMapping("addRole")
    public ResponseEntity addRole(@RequestParam Long authorityId,
                                  @RequestParam String name){
        Optional<Authority> o=authorityRepository.findById(authorityId);
        if (!o.isPresent())return ResponseEntity.notFound().build();
        Role role=roleRepository.save( Role.builder().name(name).authorities(Arrays.asList(o.get())).build());
        return ResponseEntity.ok(role);
    }


    @GetMapping("authorities")
    public ResponseEntity authorities(){
        return ResponseEntity.ok(authorityRepository.findAll());
    }

    @PostMapping("addAuthority")
    @ApiOperation(value = "添加权限")
    public ResponseEntity addAuthority(@RequestParam String name,
                                       @RequestParam String uri,
                                       @RequestParam String details){
        return ResponseEntity.ok(authorityRepository.save(Authority.builder().name(name).uri(uri).details(details).build()));
    }


    @GetMapping
    @ApiOperation(value = "测试")
    @SecurityPermission
    public ResponseEntity test(){
        return ResponseEntity.ok(jwtToken.createToken("222222222"));
    }

    @GetMapping("path")
    @SecurityPermission
    @ApiOperation(value = "获取地址")
    public ResponseEntity path(){
        return ResponseEntity.ok(testService.path());
    }

    @PostMapping("upload")
    @SecurityPermission
    @ApiOperation(value = "上传文件")
    public ResponseEntity uploadFle(@RequestParam MultipartFile file){
        return ResponseEntity.ok(testService.uploadFile(file));
    }




}



`
}

func ApplicationApp(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/Application.java", `package ` + opn + `;

import com.spring4all.swagger.EnableSwagger2Doc;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@EnableSwagger2Doc
@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

`
}
func AppInit(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/init/AppInit.java", `package ` + opn + `.config.init;

import ` + opn + `.common.bean.Config;
import ` + opn + `.common.pojo.Authority;
import ` + opn + `.common.repository.AuthorityRepository;
import ` + opn + `.config.annotation.AuthorityType;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.lang.reflect.Method;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class AppInit implements ApplicationRunner {

    @Autowired
    private WebApplicationContext applicationContext;
    @Autowired
    private AuthorityRepository authorityRepository;
    @Autowired
    private Config config;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        if (config.getAuthorityInit())new Thread(()->initData(getUrl())).run();
    }

    /**
     * 查看数据库中是否存在
     */
     private boolean checkData(String url){
         return authorityRepository.findByUri(url).isPresent();
     }

     private List<Authority> makeData(List<Map<String,String>> urls){
       return   urls.stream()
                 .filter(Objects::nonNull)
                 .filter(i->!checkData(i.get("url")))
                 .map(i->makeData(i))
                 .collect(Collectors.toList());
     }

    /**
     * 生成数据
     */
    private Authority makeData(Map<String,String> map){
        Authority a=Authority.builder().build();
        if (map.containsKey("name"))a.setName(map.get("name"));
        if (map.containsKey("url"))a.setUri(map.get("url"));
        if (map.containsKey("details"))a.setDetails(map.get("details"));
        if (map.containsKey("typeName"))a.setTypeName(map.get("typeName"));
        if (map.containsKey("type"))a.setType(Integer.valueOf(map.get("type")));
        return a;
    }

    /**
     * 数据库
     */
    private void initData(List<Map<String,String>> urls){
        authorityRepository.saveAll(makeData(urls));
    }

    /**
     * 获取url
     */
    private List<Map<String,String>> getUrl(){
        RequestMappingHandlerMapping mapping = applicationContext.getBean(RequestMappingHandlerMapping.class);
        //获取url与类和方法的对应信息
        Map<RequestMappingInfo,HandlerMethod> map = mapping.getHandlerMethods();
        List<Map<String,String>> urlList = new ArrayList<>();
        for (RequestMappingInfo info : map.keySet()){
            urlList.add(makeAuthority(info,map));
        }
        return urlList;
    }

    /**获取权限信息*/
    public  Map<String,String> makeAuthority(RequestMappingInfo info,  Map<RequestMappingInfo,HandlerMethod> map){
        HandlerMethod hm = map.get(info);
        Method m = hm.getMethod();
        Integer code=getAuthorityType(m);
        if (code==config.getAuthorityType())return null;
        Map<String,String> limitMap = new HashMap<>();
        //获取url的Set集合，一个方法可能对应多个url
        Set<String> patterns = info.getPatternsCondition().getPatterns();
        for (String url : patterns) limitMap.put("url",url);
        getAuthority(m,limitMap,code);
        return limitMap;
    }

    /**获取type类型*/
    public Integer getAuthorityType(Method m){
        // 获取方法上的注解
        AuthorityType authorityType=m.getAnnotation(AuthorityType.class);
        //获取类上的注解
        if (authorityType==null)authorityType=m.getDeclaringClass().getAnnotation(AuthorityType.class);
        if (authorityType==null)return config.getAuthorityType();
        return authorityType.code();
    }

    /**获取参数信息*/
    public void getAuthority(Method m,Map<String,String> limitMap,Integer type){
        limitMap.put("type",String.valueOf(type));
        Api api=m.getDeclaringClass().getAnnotation(Api.class);
        if (api!=null)limitMap.put("typeName",api.tags()[0]);
        if (api==null)limitMap.put("typeName",config.getAuthorityTypeName());
        ApiOperation apiOperation = m.getAnnotation(ApiOperation.class);
        Method[] me = {};
        if(apiOperation!=null) me = apiOperation.annotationType().getDeclaredMethods();
        for(Method meth : me){
            try {
                if("notes".equals(meth.getName())){
                    String color = (String) meth.invoke(apiOperation, new  Object[]{});
                    limitMap.put("details",color);
                }
                if("value".equals(meth.getName())){
                    String color = (String) meth.invoke(apiOperation, new  Object[]{});
                    limitMap.put("name",color);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
`
}
func JWTToken(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/token/JWTToken.java", `package ` + opn + `.config.token;

import ` + opn + `.common.bean.Config;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JWTToken {

    private static final int secondIn1day = 1000 * 60 * 60 * 24;

    @Autowired
    private Config config;


    //创建Token
    public  String createToken(String userId){
        long now = (new Date()).getTime();              //获取当前时间戳
        Date validity = new Date(now + secondIn1day*config.getJwtTokenValidity());
        return Jwts.builder()                                   //创建Token令牌
                .setSubject(userId)                             //设置面向用户
                .claim(config.getJwtKey(),userId)                  //添加权限属性
                .setExpiration(validity)                        //设置失效时间
                .signWith(SignatureAlgorithm.HS512,config.getJwtSecretKey())   //生成签名
                .compact();
    }


    //获取用户id
    public  String getUserId(String token){
        Claims claims = Jwts.parser()                           //解析Token的payload
                .setSigningKey(config.getJwtSecretKey())
                .parseClaimsJws(token)
                .getBody();

        return  claims.get(config.getJwtKey()).toString();
    }


    //验证Token是否正确
    public  boolean validateToken(String token){
        try {
            Jwts.parser().setSigningKey(config.getJwtSecretKey()).parseClaimsJws(token);   //通过密钥验证Token
            return true;
        } catch (Exception e) {

        }
        return false;
    }


}
`
}

func SecurityContextHolder(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/security/SecurityContextHolder.java", `package ` + opn + `.config.security;

import ` + opn + `.common.pojo.User;
import org.springframework.stereotype.Component;

@Component
public  class SecurityContextHolder {

    private static ThreadLocal<User> securityContext=new ThreadLocal<>();

    public void setUser(User user){
        securityContext.set(user);
    }

    public void removeUser(){
        securityContext.remove();
    }


    public User getUser(){
     return securityContext.get();
    }






}

`
}
func WebMvcConfig(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/mvc/WebMvcConfig.java", `package ` + opn + `.config.mvc;

import ` + opn + `.common.bean.Config;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import java.nio.file.Paths;

@Configuration
public class WebMvcConfig extends WebMvcConfigurerAdapter {

    @Autowired
    private Config config;

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/"+config.getFileUrl()+"/**").addResourceLocations("file:"+ Paths.get(config.getFilePath())+"/");

    }

}
`
}

func JsonConfig(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/json/JsonConfig.java", `package ` + opn + `.config.json;

import com.alibaba.fastjson.serializer.SerializerFeature;
import com.alibaba.fastjson.support.config.FastJsonConfig;
import com.alibaba.fastjson.support.spring.FastJsonHttpMessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class JsonConfig {
    /**
     * 定制HTTP消息转换器
     * @return
     */
    @Bean
    public HttpMessageConverter fastJsonConverters(){
        // 1.定义一个convert 转换消息的对象
        FastJsonHttpMessageConverter fastConverter = new FastJsonHttpMessageConverter();
        // 2 添加fastjson 的配置信息 比如 是否要格式化 返回的json数据
        FastJsonConfig fastJsonConfig = new FastJsonConfig();
        //格式化
        fastJsonConfig.setSerializerFeatures(SerializerFeature.PrettyFormat);
        //null属性显示
        fastJsonConfig.setSerializerFeatures(SerializerFeature.WriteNullStringAsEmpty);
        fastConverter.setFastJsonConfig(fastJsonConfig);
        // 解决乱码的问题
        List<MediaType> fastMediaTypes = new ArrayList<MediaType>();
        fastMediaTypes.add(MediaType.APPLICATION_JSON_UTF8);
        fastConverter.setSupportedMediaTypes(fastMediaTypes);
        HttpMessageConverter<?> converter = fastConverter;
        return converter;
    }
}
`
}

func WebAppConfigurer(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/mvc/WebAppConfigurer.java", `package ` + opn + `.config.mvc;

import ` + opn + `.common.bean.Config;
import ` + opn + `.config.interceptor.SecurityInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.nio.file.Paths;
import java.util.Arrays;


@Configuration
public class WebAppConfigurer implements WebMvcConfigurer {



    @Autowired
    private SecurityInterceptor securityInterceptor;
    @Autowired
    private Config config;



    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 多个拦截器组成一个拦截器链
        // addPathPatterns 用于添加拦截规则
        // excludePathPatterns 用户排除拦截
//        InterceptorRegistration in=registry.addInterceptor(authorizationInterceptor);
//        setPath(config,in);

        registry.addInterceptor(securityInterceptor)
                .excludePathPatterns("/static/*")
                .excludePathPatterns("/error")
                .excludePathPatterns("/"+config.getFileUrl()+"/**")
                .addPathPatterns("/**");


    }


    /**获取路径*/
    public static String[] path(String str){
        return str.split(",");
    }


    /**设置路径*/
    public static void setPath(Config properties, InterceptorRegistration http) {
        String[] addPath=path(properties.getAddPath());
        String[] excludePath=path(properties.getExcludePath());
        Arrays.stream(addPath).forEach(i->http.addPathPatterns(i));
        Arrays.stream(excludePath).forEach(i->http.excludePathPatterns(i));
    }

      @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
//        registry.addResourceHandler("/static/**").addResourceLocations("classpath:/static/");
        registry.addResourceHandler("/"+config.getFileUrl()+"/**").addResourceLocations("file:"+ Paths.get(config.getFilePath())+"/");

    }



}

`
}

func SecurityInterceptor(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/interceptor/SecurityInterceptor.java", `package ` + opn + `.config.interceptor;

import com.alibaba.fastjson.JSON;
import ` + opn + `.common.bean.Config;
import ` + opn + `.common.pojo.Role;
import ` + opn + `.common.pojo.User;
import ` + opn + `.common.repository.UserRepository;
import ` + opn + `.config.annotation.SecurityPermission;
import ` + opn + `.config.security.SecurityContextHolder;
import ` + opn + `.config.token.JWTToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;

import static ` + opn + `.common.bean.Result.auth;


@Component
public class SecurityInterceptor extends HandlerInterceptorAdapter {


    @Autowired
    private Config config;
    @Autowired
    private JWTToken jwtToken;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private SecurityContextHolder securityContextHolder;



    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        //如果不是映射到方法直接通过
        if (!(handler instanceof HandlerMethod)) return true;
        if (hasPermission(request,handler))return true;
        response(response);
        return false;
    }

    @Override
    //整个请求执行完成后调用
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        super.afterCompletion(request, response, handler, ex);
        securityContextHolder.removeUser();
    }


    private boolean hasPermission(HttpServletRequest request,Object handler) {
            HandlerMethod handlerMethod = (HandlerMethod) handler;
            String token=request.getHeader(config.getAuthorization());
            //获取类上的注解
            SecurityPermission requiredPermission=handlerMethod.getMethod().getDeclaringClass().getAnnotation(SecurityPermission.class);
            // 获取方法上的注解
            if (requiredPermission==null) requiredPermission = handlerMethod.getMethod().getAnnotation(SecurityPermission.class);
            if (requiredPermission==null)return true;
            if (!"".equals(requiredPermission.value())&&permission(request.getRequestURI(),requiredPermission.value()))return true;
            if (Optional.ofNullable(token).isPresent()&& jwtToken.validateToken(token)&&jwtToken.getUserId(token)!=null)return permissionUser(request.getRequestURI(),jwtToken.getUserId(token));
            return false;
    }

    private boolean permissionUser(String uri,String id){
        boolean flag=false;
        Optional<User> o=userRepository.findById(Long.valueOf(id));
        if (!o.isPresent())return false;
        List<Role> roles=o.get().getRoles();
        if (checkAdmin(roles))return setUser(o.get());
        for (int i=0;i<roles.size();i++){
            for (int j=0;j<roles.get(i).getAuthorities().size();j++){
                if (uri.equals(roles.get(i).getAuthorities().get(j).getUri())){
                    flag=setUser(o.get());
                    break;
                }
            }
        }
        return flag;
    }

    private boolean checkAdmin(List<Role> roles){
        boolean flag=false;
        for (int i=0;i<roles.size();i++){
            if (config.getAuthorityAdmin().equals(roles.get(i).getCode())){
                flag=true;
                break;
            }
        }
        return flag;
    }

    private boolean setUser(User user){
        user.setRoles(new ArrayList<>());
        securityContextHolder.setUser(user);
        return true;
    }

    private boolean permission(String uri,String value){
        boolean flag=false;
        String[]s = value.split(",");
        Set<String> strings=new LinkedHashSet<>();
        Arrays.stream(s).forEach((v)->strings.add(v));
        String[] ss=uri.split("/");
        for (int i=0;i<ss.length;i++){
            if (strings.contains(ss[i])){
                flag=true;
                break;
            }
        }
        return flag;
    }

    /**
     * 返回错误信息
     */
    public void response(HttpServletResponse response){
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        PrintWriter out= null;
        try {
            out = response.getWriter();
            out.write(JSON.toJSONString(auth()));
            out.flush();
        } catch (IOException e) {
        }finally {
            out.close();
        }

    }

}
`
}

func AuthorizationInterceptor(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/interceptor/AuthorizationInterceptor.java", `package ` + opn + `.config.interceptor;

import com.alibaba.fastjson.JSON;
import ` + opn + `.common.bean.Config;
import ` + opn + `.common.pojo.User;
import ` + opn + `.common.repository.UserRepository;
import ` + opn + `.config.security.SecurityContextHolder;
import ` + opn + `.config.token.JWTToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Optional;

import static ` + opn + `.common.bean.Result.over;


/**
 * 自定义拦截器，判断此次请求是否有权限
 *
 *
 */
@Component
public class AuthorizationInterceptor extends HandlerInterceptorAdapter {


    @Autowired
    private Config config;
    @Autowired
    private JWTToken jwtToken;
    @Autowired
    private SecurityContextHolder securityContextHolder;
    @Autowired
    private UserRepository userRepository;



    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        //如果不是映射到方法直接通过
        if (!(handler instanceof HandlerMethod)) return true;
        String token=request.getHeader(config.getAuthorization());
        if (Optional.ofNullable(token).isPresent()&& jwtToken.validateToken(token)&&jwtToken.getUserId(token)!=null){
            Optional<User> o=userRepository.findById(Long.valueOf(jwtToken.getUserId(token)));
            if (o.isPresent())return true;
        }
        //如果验证token失败，返回错误信息
        response(response);
        return false;
    }

    @Override
    //在后端控制器执行后调用
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
        super.postHandle(request, response, handler, modelAndView);
    }

    @Override
    //整个请求执行完成后调用
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        super.afterCompletion(request, response, handler, ex);
        securityContextHolder.removeUser();
    }




    /**
     * 返回错误信息
     */
    public void response(HttpServletResponse response){
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        PrintWriter out= null;
        try {
            out = response.getWriter();
            out.write(JSON.toJSONString(over()));
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }finally {
            out.close();
        }

    }


}


`
}

func Http2Config(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/http2/Http2Config.java", `package ` + opn + `.config.http2;

import io.undertow.UndertowOptions;
import org.springframework.boot.web.embedded.undertow.UndertowServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class Http2Config {

    @Bean
    UndertowServletWebServerFactory undertowServletWebServerFactory() {
        UndertowServletWebServerFactory factory = new UndertowServletWebServerFactory();
        factory.addBuilderCustomizers(
                builder -> {
                    builder.setServerOption(UndertowOptions.ENABLE_HTTP2, true)
                            .setServerOption(UndertowOptions.HTTP2_SETTINGS_ENABLE_PUSH,true);
                });

        return factory;
    }
}
`
}

func CustomCorsConfiguration(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/cors/CustomCorsConfiguration.java", `package ` + opn + `.config.cors;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;



/**
 * 服务器跨域处理
 */
@Configuration
public class CustomCorsConfiguration {



    /***
     * 在spring MVC 中可以配置全局的规则，
     * 也可以使用@CrossOrigin注解进行细粒度的配置。
     * @return
     */

    @Bean
    public FilterRegistrationBean corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("OPTION");
        config.addAllowedMethod("GET");
        config.addAllowedMethod("POST");
        config.addAllowedMethod("PUT");
        config.addAllowedMethod("HEAD");
        config.addAllowedMethod("DELETE");
        source.registerCorsConfiguration("/**", config);
        FilterRegistrationBean bean = new FilterRegistrationBean(new CorsFilter(source));
        bean.setOrder(0);
        return bean;
    }

    @Bean
    public WebMvcConfigurer mvcConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**").allowedMethods("GET", "PUT", "POST", "GET", "OPTIONS");
            }
        };
    }







}

`
}

func AuthorAspect(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/aop/AuthorAspect.java", `package ` + opn + `.config.aop;

import ` + opn + `.common.bean.Result;
import ` + opn + `.common.bean.Tips;
import ` + opn + `.common.pojo.User;
import ` + opn + `.config.annotation.Author;
import ` + opn + `.config.security.SecurityContextHolder;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

@Aspect
@Component
public class AuthorAspect {



    @Autowired
    private SecurityContextHolder securityContextHolder;
    private Map<String,String> roleMap=new HashMap<>();

    @Pointcut(value = "@annotation(` + opn + `.config.annotation.Author)")
    public void aspect(){

    }

    /**
     * 在调用通知方法之前和之后运行通知。
     * @param joinPoint
     * @return
     */
    @Around(value = "aspect()")
    public Object around(ProceedingJoinPoint joinPoint){
        Author annotation=((MethodSignature)joinPoint.getSignature()).getMethod().getAnnotation(Author.class);
        if (!getUser()) return Result.fail(Tips.USER_NOT.msg);
        try {
            if ("".equals(annotation.value())) return joinPoint.proceed();
            if (checkRole(annotation.value()))return joinPoint.proceed();
            return Result.auth();
        } catch (Throwable throwable) {
            throwable.printStackTrace();
        }
        return Result.fail(Tips.USER_NOT.msg);
    }


    /**
     * 获取用户信息
     *
     */
    public boolean getUser(){
        User user=securityContextHolder.getUser();
        if (user!=null) return true;
        return true;
    }


    private boolean checkRole(String str){
        Map<String,String> rx=getRole(str);
        List<String> roles=securityContextHolder
                .getUser()
                .getRoles()
                .stream()
                .map(i->i.getName())
                .collect(Collectors.toList());
        for (int i=0;i<roles.size();i++){
            if (rx.containsKey(String.valueOf(roles.get(i)))){
                return true;
            }
        }
        return false;
    }

    private Map<String,String> getRole(String str){
        roleMap.clear();
        Arrays.stream(str.split(",")).forEach(i->roleMap.put(i,i));
        return roleMap;
    }




}

`
}

func EncryptRequestBodyAdvice(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/advice/EncryptRequestBodyAdvice.java", `package ` + opn + `.config.advice;

import ` + opn + `.common.bean.Config;
import ` + opn + `.common.util.AesEncryptUtils;
import ` + opn + `.common.util.IOUtils;
import ` + opn + `.config.annotation.Decrypt;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;


/**
 * 请求数据接收处理类<br>
 * 
 * 对加了@Decrypt的方法的数据进行解密操作<br>
 * 
 * 只对@RequestBody参数有效
 *
 *
 */
@ControllerAdvice
@Slf4j
public class EncryptRequestBodyAdvice implements RequestBodyAdvice {

	
	@Autowired
	private Config config;
	
	@Override
	public boolean supports(MethodParameter methodParameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
		return true;
	}

	@Override
	public Object handleEmptyBody(Object body, HttpInputMessage inputMessage, MethodParameter parameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
		return body;
	}

	@Override
	public HttpInputMessage beforeBodyRead(HttpInputMessage inputMessage, MethodParameter parameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) throws IOException {
		if(parameter.getMethod().isAnnotationPresent(Decrypt.class) && !config.isAesDebug()){
			try {
				return new DecryptHttpInputMessage(inputMessage, config.getAesKey(), config.getAesCharset());
			} catch (Exception e) {
				log.error("数据解密失败", e);
			}
		}
		return inputMessage;
	}

	@Override
	public Object afterBodyRead(Object body, HttpInputMessage inputMessage, MethodParameter parameter, Type targetType,
			Class<? extends HttpMessageConverter<?>> converterType) {
		return body;
	}
}

class DecryptHttpInputMessage implements HttpInputMessage {
	private Logger logger = LoggerFactory.getLogger(EncryptRequestBodyAdvice.class);
    private HttpHeaders headers;
    private InputStream body;

    public DecryptHttpInputMessage(HttpInputMessage inputMessage, String key, String charset) throws Exception {
        this.headers = inputMessage.getHeaders();
        String content = IOUtils.toString(inputMessage.getBody(), charset);
        long startTime = System.currentTimeMillis();
        // JSON 数据格式的不进行解密操作
        String decryptBody = "";
        if (content.startsWith("{")) {
        	decryptBody = content;
		} else {
			decryptBody = AesEncryptUtils.aesDecrypt(content, key);
		}
        long endTime = System.currentTimeMillis();
		logger.debug("Decrypt Time:" + (endTime - startTime));
        this.body = IOUtils.toInputStream(decryptBody, charset);
    }

    @Override
    public InputStream getBody() throws IOException {
        return body;
    }

    @Override
    public HttpHeaders getHeaders() {
        return headers;
    }
}

`
}

func EncryptResponseBodyAdvice(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/advice/EncryptResponseBodyAdvice.java", `package ` + opn + `.config.advice;

import com.fasterxml.jackson.databind.ObjectMapper;
import ` + opn + `.common.bean.Config;
import ` + opn + `.common.util.AesEncryptUtils;
import ` + opn + `.config.annotation.Encrypt;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

/**
 * 请求响应处理类<br>
 * 对加了@Encrypt的方法的数据进行加密操作
 */
@ControllerAdvice
@Slf4j
public class EncryptResponseBodyAdvice implements ResponseBodyAdvice<Object> {

    @Autowired
    private Config config;
    private static ThreadLocal<Boolean> encryptLocal = new ThreadLocal<Boolean>();
    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public boolean supports(MethodParameter methodParameter, Class<? extends HttpMessageConverter<?>> aClass) {
        return true;
    }

    @Override
    public Object beforeBodyWrite(Object o, MethodParameter methodParameter, MediaType mediaType, Class<? extends HttpMessageConverter<?>> aClass, ServerHttpRequest serverHttpRequest, ServerHttpResponse serverHttpResponse) {
        Boolean status = encryptLocal.get();
        if (status != null && status == false) {
            encryptLocal.remove();
            return o;
        }
        long startTime = System.currentTimeMillis();
        boolean encrypt = false;
        if (methodParameter.getMethod().isAnnotationPresent(Encrypt.class) && !config.isAesDebug()) {
            encrypt = true;
        }
        if (encrypt) {
            try {
                String content = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(o);
                String result =  AesEncryptUtils.aesEncrypt(content, config.getAesKey());
                long endTime = System.currentTimeMillis();
                log.debug("Encrypt Time:" + (endTime - startTime));
                return result;
            } catch (Exception e) {
                log.error("加密数据异常", e);
            }
        }

        return o;

    }
}

`
}

func AuthorityType(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/annotation/AuthorityType.java", `package ` + opn + `.config.annotation;
import java.lang.annotation.*;

@Target({ElementType.PARAMETER, ElementType.METHOD,ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AuthorityType {


    int code() default 0;

}


`
}

func SecurityPermission(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/annotation/SecurityPermission.java", `package ` + opn + `.config.annotation;

import java.lang.annotation.*;

@Target({ElementType.PARAMETER, ElementType.METHOD,ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface SecurityPermission {

    String value()  default "";

}

`
}

func Encrypt(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/annotation/Encrypt.java", `package ` + opn + `.config.annotation;

import java.lang.annotation.*;

/**
 * 加密注解
 * 
 * <p>加了此注解的接口将进行数据加密操作<p>
 *
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Encrypt {

}

`
}

func Decrypt(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/annotation/Decrypt.java", `package ` + opn + `.config.annotation;

import java.lang.annotation.*;

/**
 * 解密注解
 * 
 * <p>加了此注解的接口将进行数据解密操作<p>
 *
 *
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Decrypt {

}

`
}

func Author(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/config/annotation/Author.java", `package ` + opn + `.config.annotation;

import java.lang.annotation.*;


@Target({ElementType.PARAMETER, ElementType.METHOD,ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Author {

    String value()  default "";


}
`
}

func StringBuilderWriter(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/common/util/StringBuilderWriter.java", `package ` + opn + `.common.util;

import java.io.Serializable;
import java.io.Writer;

public class StringBuilderWriter extends Writer implements Serializable {
    private static final long serialVersionUID = -146927496096066153L;
    private final StringBuilder builder;

    public StringBuilderWriter() {
        this.builder = new StringBuilder();
    }

    public StringBuilderWriter(int capacity) {
        this.builder = new StringBuilder(capacity);
    }

    public StringBuilderWriter(StringBuilder builder) {
        this.builder = builder != null ? builder : new StringBuilder();
    }

    public Writer append(char value) {
        this.builder.append(value);
        return this;
    }

    public Writer append(CharSequence value) {
        this.builder.append(value);
        return this;
    }

    public Writer append(CharSequence value, int start, int end) {
        this.builder.append(value, start, end);
        return this;
    }

    public void close() {
    }

    public void flush() {
    }

    public void write(String value) {
        if (value != null) {
            this.builder.append(value);
        }

    }

    public void write(char[] value, int offset, int length) {
        if (value != null) {
            this.builder.append(value, offset, length);
        }

    }

    public StringBuilder getBuilder() {
        return this.builder;
    }

    public String toString() {
        return this.builder.toString();
    }
}

`
}

func IOUtils(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/common/util/IOUtils.java", `package ` + opn + `.common.util;

import java.io.*;


public class IOUtils {




    public static InputStream toInputStream(String input, String encoding) throws IOException {
        byte[] bytes = input.getBytes(encoding);
        return new ByteArrayInputStream(bytes);
    }

    public static void write(byte[] data, OutputStream output) throws IOException {
        if (data != null) {
            output.write(data);
        }

    }


    public static String toString(InputStream input, String encoding) throws IOException {
        StringBuilderWriter sw = new StringBuilderWriter();
        Throwable var3 = null;

        String var4;
        try {
            copy((InputStream)input, (Writer)sw, encoding);
            var4 = sw.toString();
        } catch (Throwable var13) {
            var3 = var13;
            throw var13;
        } finally {
            if (sw != null) {
                if (var3 != null) {
                    try {
                        sw.close();
                    } catch (Throwable var12) {
                        var3.addSuppressed(var12);
                    }
                } else {
                    sw.close();
                }
            }

        }

        return var4;
    }

    public static void copy(InputStream input, Writer output, String charset) throws IOException {
        InputStreamReader in = new InputStreamReader(input, charset);
        copy((Reader)in, (Writer)output);
    }

    public static int copy(Reader input, Writer output) throws IOException {
        long count = copyLarge(input, output);
        return count > 2147483647L ? -1 : (int)count;
    }
    public static long copyLarge(Reader input, Writer output) throws IOException {
        return copyLarge(input, output, new char[4096]);
    }

    public static long copyLarge(Reader input, Writer output, char[] buffer) throws IOException {
        long count;
        int n;
        for(count = 0L; -1 != (n = input.read(buffer)); count += (long)n) {
            output.write(buffer, 0, n);
        }

        return count;
    }

}

`
}

func AesEncryptUtils(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/common/util/AesEncryptUtils.java", `package ` + opn + `.common.util;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AesEncryptUtils {
	private static final String ALGORITHMSTR = "AES/ECB/PKCS5Padding";

	public static String base64Encode(byte[] bytes) {
		return Base64.getEncoder().encodeToString(bytes);
	}

	public static byte[] base64Decode(String base64Code) throws Exception {
		return Base64.getDecoder().decode(base64Code);
	}

	public static byte[] aesEncryptToBytes(String content, String encryptKey) throws Exception {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128);
		Cipher cipher = Cipher.getInstance(ALGORITHMSTR);
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptKey.getBytes(), "AES"));
		return cipher.doFinal(content.getBytes("utf-8"));
	}

	public static String aesEncrypt(String content, String encryptKey) throws Exception {
		return base64Encode(aesEncryptToBytes(content, encryptKey));
	}

	public static String aesDecryptByBytes(byte[] encryptBytes, String decryptKey) throws Exception {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128);
		Cipher cipher = Cipher.getInstance(ALGORITHMSTR);
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptKey.getBytes(), "AES"));
		byte[] decryptBytes = cipher.doFinal(encryptBytes);
		return new String(decryptBytes);
	}

	public static String aesDecrypt(String encryptStr, String decryptKey) throws Exception {
		return aesDecryptByBytes(base64Decode(encryptStr), decryptKey);
	}

	
}
`
}

func PathUtils(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/common/util/PathUtils.java", `package ` + opn + `.common.util;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

public class PathUtils {




    /***
     *  路径转换
     */
    public static String pathToPath(String str){
        String path=null;
        if("\\".equals(File.separator)){
            //windows下
            path=str+"\\";
        }else if("/".equals(File.separator)){
            //linux下
            path=str+"/";
        }else {
            path=str;
        }
        return path;
    }

    /**
     * 获取nio path
     * @param str
     * @return
     */
    public static Path getPath(String str){
        return Paths.get(pathToPath(str));
    }



}

`
}

func FileUtils(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/common/util/FileUtils.java", `package ` + opn + `.common.util;

import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Component
public class FileUtils {



    /**
     * base64上传文件
     *
     *
     */
    public String base64SaveFile(Path path,String data,String type){
        try {
            String root=PathUtils.pathToPath(String.valueOf(path))+dateToString();
            String key=getUuid()+"."+type;
            if(!Files.exists(FileSystems.getDefault().getPath(root))) Files.createDirectories(FileSystems.getDefault().getPath(root));
            byte[] bytes=Base64.getDecoder().decode(data);
            for (int i = 0; i < bytes.length; ++i) {
                if (bytes[i] < 0) {// 调整异常数据
                    bytes[i] += 256;
                }
            }
            // 生成jpeg图片
            Files.copy(new ByteArrayInputStream(bytes), Paths.get(root).resolve(key));
            return dateToString()+"/"+key;
        }catch (Exception e){
          e.printStackTrace();
        }
        return null;
    }



    public String saveFile(String path, MultipartFile file) throws IOException {
        if (path==null||file.isEmpty()) return null;
        String root=PathUtils.pathToPath(String.valueOf(path))+dateToString();
        String fileName = file.getOriginalFilename();
        //获取文件类型
        String suffix = fileName.substring(fileName.lastIndexOf(".") + 1);
        //文件名
        String key=getUuid()+"."+suffix;
        if(!Files.exists(FileSystems.getDefault().getPath(root))) Files.createDirectories(FileSystems.getDefault().getPath(root));
        if (suffix==null)return null;
        FileOutputStream fos=new FileOutputStream(new File( Paths.get(root).resolve(key).toUri()));
        FileChannel out=fos.getChannel();
        InputStream is=file.getInputStream();
        int capacity = 1024;// 字节
        ByteBuffer bf = ByteBuffer.allocate(capacity);
       for (int i=0;i<is.available();i++){






       }

        return null;
    }






    /***
     * 保存文件到磁盘
     * @param path
     * @param file
     * @return
     * @throws IOException
     */


    public  String saveFile(Path path, MultipartFile file) {
        try {
            if (file.isEmpty()) return null;
            String root=PathUtils.pathToPath(String.valueOf(path))+dateToString();
            //获取文件类型
            String fileType=getFileType(file);
            //文件名
            String key=getUuid()+"."+fileType;
            if(!Files.exists(FileSystems.getDefault().getPath(root))) Files.createDirectories(FileSystems.getDefault().getPath(root));
            if (fileType==null)return null;
            Files.copy(file.getInputStream(), Paths.get(root).resolve(key));
            return dateToString()+"/"+key;
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 获取上传文件类型
     */
    public  String getFileType(MultipartFile file){
        String[] s = file.getOriginalFilename().split("\\.");
        List list = new ArrayList();
        for (String s1 : s) {
            list.add(s1);
        }
        if(list.size()>1){
            return list.get(list.size()-1).toString();
        }
        return null;
    }


    /**
     * 获取UUID作为文件名
     */
    public String getUuid(){
        return UUID.randomUUID().toString().replaceAll("-","");
    }


    /**
     * date>>string
     * yyyyMMdd
     */
    public static String dateToString(){
        return LocalDate.now().format(DateTimeFormatter.ofPattern("yyyyMM"));

    }





}

`
}

func PasswordEncoderUtils(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/common/util/PasswordEncoderUtils.java", `package ` + opn + `.common.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PasswordEncoderUtils {


    private static BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


    public static String encode(String password){
        return passwordEncoder.encode(password);
    }

    public static Boolean decode(String password,String encodePassword){
        if (password==null||encodePassword==null)return false;
        return passwordEncoder.matches(password,encodePassword);
    }


   public static void main(String[]args){

        System.out.println(encode("123456"));
        System.out.println(decode("1234565",encode("123456")));

   }




}
`
}

func AuthorityRepository(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/common/repository/AuthorityRepository.java", `package ` + opn + `.common.repository;

import ` + opn + `.common.pojo.Authority;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface AuthorityRepository extends JpaRepository<Authority,Long> {


 Optional<Authority> findByUri(String uri);




}

`
}

func RoleRepository(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/common/repository/RoleRepository.java", `package ` + opn + `.common.repository;

import ` + opn + `.common.pojo.Role;
import org.springframework.data.jpa.repository.JpaRepository;


public interface RoleRepository extends JpaRepository<Role,Long> {








}`
}

func UserRepository(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/common/repository/UserRepository.java", `package ` + opn + `.common.repository;
import ` + opn + `.common.pojo.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Long> {

    Optional<User> findByUsername(String username);

}
`
}

func Role(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/common/pojo/Role.java", `package ` + opn + `.common.pojo;

import com.alibaba.fastjson.annotation.JSONField;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.List;


@Builder
@Entity
@Data
@Table(name = "s_role")
@AllArgsConstructor
@NoArgsConstructor
public class Role {


    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String code;
    @ManyToMany(targetEntity = User.class,mappedBy = "roles")
    @JSONField(serialize = false)
    private List<User> users;
    @ManyToMany(cascade=CascadeType.REFRESH,fetch = FetchType.LAZY)
    @JoinTable(inverseJoinColumns=@JoinColumn(name="authority_id"), joinColumns=@JoinColumn(name="role_id"))
    private List<Authority> authorities;






}

`
}

func Authority(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/common/pojo/Authority.java", `package ` + opn + `.common.pojo;

import com.alibaba.fastjson.annotation.JSONField;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.List;

@Builder
@Entity
@Data
@Table(name = "s_authority")
@AllArgsConstructor
@NoArgsConstructor
public class Authority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    /**权限名*/
    private String name;
    /**类别*/
    private Integer type;
    /**类别名*/
    private String typeName;
    /**权限uri*/
    private String uri;
    /**详细描述*/
    private String details;
    @ManyToMany(cascade=CascadeType.REFRESH,mappedBy="authorities",fetch = FetchType.EAGER)
    @JSONField(serialize = false)
    private List<Role> roles;











}

`
}

func User(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/common/pojo/User.java", `package ` + opn + `.common.pojo;
import com.alibaba.fastjson.annotation.JSONField;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;


@Entity
@Data
@Builder
@Table(name = "s_user",uniqueConstraints = {@UniqueConstraint(columnNames = "username")},indexes = {@Index(columnList = "username")})
@AllArgsConstructor
@NoArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;
    @JsonFormat(pattern="yyyy-MM-dd HH:mm:ss")
    private LocalDateTime createTime;
    @ManyToMany(targetEntity = Role.class,fetch = FetchType.LAZY)
    @JoinTable(joinColumns={@JoinColumn(name="user_id")}, inverseJoinColumns={@JoinColumn(name="role_id")})
    @JSONField(serialize = false)
    private List<Role> roles=new ArrayList<>();
    @Transient
    private String token;

}

`
}

func UserMapperA(n, pn, opn string) (string, string) {
	return n + "/src/main/java" + pn + "/common/mapper/UserMapper.java", `package ` + opn + `.common.mapper;


import ` + opn + `.common.pojo.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface UserMapper {

    @Select("select * from s_user")
    List<User> findAll();



}
`
}

func Tips(n, pn, opn string) (string, string) {

	return n + "/src/main/java" + pn + "/common/bean/Tips.java", `package ` + opn + `.common.bean;
public enum Tips {


    FAIL(0,"失败"),
    SUCCESS(1,"成功"),
    DISABLED_TOEK(2,"token过期"),
    AUTHOR_NO(3,"没有访问权限"),
    USER_NOT("用户信息不存在"),
    PASSWORD_FALSE("密码错误"),
    TYPE_FALSE("文件类型不支持"),
    PROJECT_HAD("项目信息已存在")

    ;


    public Integer code;
    public String msg;


    Tips(String msg) {
        this.msg = msg;
    }

    Tips(Integer code, String msg) {
        this.code = code;
        this.msg = msg;
    }


}
`
}

func Result(n, pn, opn string) (string, string) {

	return n + "/src/main/java" + pn + "/common/bean/Result.java", `package ` + opn + `.common.bean;

public class Result {


    private Integer code;
    private String msg="";
    private Object data="";


    public Result(Integer code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public Result(Integer code, String msg, Object data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }

    public static Result auth(){
        return new Result(Tips.AUTHOR_NO.code,Tips.AUTHOR_NO.msg);
    }

    public static Result over(){
        return new Result(Tips.DISABLED_TOEK.code,Tips.DISABLED_TOEK.msg);
    }

    public static Result success(){
        return new Result(Tips.SUCCESS.code,Tips.SUCCESS.msg);
    }

    public static Result success(String msg,Object data){
        return new Result(Tips.SUCCESS.code,msg,data);
    }

    public static Result success(Object data){
        return new Result(Tips.SUCCESS.code,Tips.SUCCESS.msg,data);
    }

    public static Result fail(){
        return new Result(Tips.FAIL.code,Tips.FAIL.msg);
    }

    public static Result fail(String msg){
        return new Result(Tips.FAIL.code,msg);
    }

    public static Result fail(Integer code,String msg){
        return new Result(code,msg);
    }


    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }
}
`
}

func Config(n, pn, opn string) (string, string) {

	return n + "/src/main/java" + pn + "/common/bean/Config.java",
		`package ` + opn + `.common.bean;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix ="config" )
public class Config {
    /**
     * 请求头
     */
    private String authorization = "authorization";
    /**
     * 存储当前登录token
     */
    private String token = "authorization";
    /**
     * JWT字段名
     */
    private String jwtKey = "AUTHORITIES_KEY";
    /**
     * JWT签名密钥
     */
    private String jwtSecretKey = "secretKey";
    /**
     * JWT有效期
     */
    private Long jwtTokenValidity = 7L;

    /**拦截uri*/
    private String addPath="/token/**";
    /**不拦截uri*/
    private String excludePath="/test/**";

   /**端口号*/
    private Integer filePort=8080;
    /**本地文件地址*/
    private String  filePath;
    /**IP地址*/
    private String  fileHost;
    /**请求地址*/
    private String  fileUrl="/upload/**";
    /**设置不能上传的文件类型*/
    private String  fileType="php,java,jsp";

    /**权限管理的 超级管理员角色*/
    private String authorityAdmin="admin";
    /**权限管理 是否初始化 权限*/
    private Boolean authorityInit=false;
    /**权限类型 默认分类*/
    private Integer authorityType=0;
    private String authorityTypeName="测试";
    /**AES加密KEY*/
    private String aesKey="QAZWSXEDCR123456";
    /**字符集*/
    private String aesCharset="UTF-8";
    /**
     * 开启调试模式，调试模式下不进行加解密操作，用于像Swagger这种在线API测试场景
     */
    private boolean aesDebug = false;





}


`

}

func UserMapper(n string) (string, string) {
	return n + "/src/main/resources/mybatis/mapper/user_mapper.xml", `<?xml version="1.0" encoding="utf-8" ?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.ly.civil.common.mapper.UserMapper">


</mapper>`
}

func MybatisConfig(n string) (string, string) {

	return n + "/src/main/resources/mybatis/mybatis-config.xml", `<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE configuration PUBLIC "-//mybatis.org//DTD Config 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-config.dtd">
<configuration>

    <settings>
        <!-- 使用jdbc的getGeneratedKeys获取数据库自增主键值 -->
        <setting name="useGeneratedKeys" value="true"></setting>
        <!-- 使用列别名替换列名 默认:true -->
        <setting name="useColumnLabel" value="true"></setting>
        <!-- 开启驼峰命名转换:Table{create_time} -> Entity{createTime} -->
        <setting name="mapUnderscoreToCamelCase" value="true"/>
        <!-- 打印查询语句 -->
        <setting name="logImpl" value="STDOUT_LOGGING" />
    </settings>

    <typeAliases>
        <!--
        通过package, 可以直接指定package的名字， mybatis会自动扫描你指定包下面的javabean,
        并且默认设置一个别名，默认的名字为： javabean 的首字母小写的非限定类名来作为它的别名。
        也可在javabean 加上注解@Alias 来自定义别名， 例如： @Alias(user)
         <typeAlias alias="UserEntity" type="com.dy.entity.User"/>
        <package name="com.dy.entity"/>
         -->
        <!--<package name="com.example.ssm.common.pojo"/>-->
    </typeAliases>
    <!-- 配置全局属性 -->

</configuration>`

}

func ApplicationProd(n string) (string, string) {

	return n + "/src/main/resources/config/application-prod.yml", `
###mysql配置
mysqlPort: 3306
mysqlHost: 47.92.213.93
mysqlUserName: root
mysqlPassword: liaolin2018
mysqlDriver: com.mysql.jdbc.Driver
mysqlDateBase: test
mysqlUrl: jdbc:mysql://${mysqlHost}:${mysqlPort}/${mysqlDateBase}?useUnicode=true&characterEncoding=utf-8&useSSL=false&serverTimezone=GMT%2B8

swagger:
  enabled: false

####druid 链接池
spring:
  jpa:
      properties:
         hibernate:
            dialect: org.hibernate.dialect.MySQL5InnoDBDialect
            format_sql: true
            hbm2ddl:
                 auto: update
      show-sql: true
      #packages: com.ly.spider.common.pojo
  datasource:
    druid:
      url: ${mysqlUrl}
      username: ${mysqlUserName}
      password: ${mysqlPassword}
      driver-class-name: ${mysqlDriver}
      # 初始化大小，最小，最大
      initialSize: 5
      minIdle: 5
      maxActive: 20
      # 配置获取连接等待超时的时间
      maxWait: 10000
      # 配置间隔多久才进行一次检测，检测需要关闭的空闲连接，单位是毫秒
      timeBetweenEvictionRunsMillis: 60000
      # 配置一个连接在池中最小生存的时间，单位是毫秒
      minEvictableIdleTimeMillis: 300000
      validationQuery: SELECT 1 FROM DUAL
      #建议配置为true，不影响性能，并且保证安全性。申请连接的时候检测，
      #如果空闲时间大于timeBetweenEvictionRunsMillis，执行validationQuery检测连接是否有效。
      testWhileIdle: true
      #申请连接时执行validationQuery检测连接是否有效，做了这个配置会降低性能。
      testOnBorrow: false
      testOnReturn: false
      # 打开PSCache，并且指定每个连接上PSCache的大小
      poolPreparedStatements: true
      maxPoolPreparedStatementPerConnectionSize: 20
      filter:
        # 配置StatFilter
       stat:
         db-type: h2
         log-slow-sql: true
         slow-sql-millis: 2000
       # 配置WallFilter
       wall:
         enabled: true
         db-type: h2
         config:
           delete-allow: true
           drop-table-allow: false


mybatis:
  config-location: classpath:mybatis/mybatis-config.xml
  mapper-locations: classpath:mybatis/mapper/*.xml

`
}

func ApplicationDev(n string) (string, string) {
	return n + "/src/main/resources/config/application-dev.yml", `
###mysql配置
mysqlPort: 3306
mysqlHost: 47.92.213.93
mysqlUserName: root
mysqlPassword: liaolin2018
mysqlDriver: com.mysql.cj.jdbc.Driver
mysqlDateBase: test
mysqlUrl: jdbc:mysql://${mysqlHost}:${mysqlPort}/${mysqlDateBase}?useUnicode=true&characterEncoding=utf-8&useSSL=false&serverTimezone=GMT%2B8

swagger:
  enabled: true
  title: TEST Api
  authorization:
    key-name: authorization
  docket:
    test:
      base-package: com.ly.boot.module.test
    user:
      base-package: com.ly.boot.module.user


####druid 链接池
spring:
  jpa:
      properties:
         hibernate:
            dialect: org.hibernate.dialect.MySQL5InnoDBDialect
            format_sql: true
            hbm2ddl:
                 auto: update
      show-sql: true
      #packages: com.ly.spider.common.pojo
  datasource:
    druid:
      url: ${mysqlUrl}
      username: ${mysqlUserName}
      password: ${mysqlPassword}
      driver-class-name: ${mysqlDriver}
      # 初始化大小，最小，最大
      initialSize: 5
      minIdle: 5
      maxActive: 20
      # 配置获取连接等待超时的时间
      maxWait: 10000
      # 配置间隔多久才进行一次检测，检测需要关闭的空闲连接，单位是毫秒
      timeBetweenEvictionRunsMillis: 60000
      # 配置一个连接在池中最小生存的时间，单位是毫秒
      minEvictableIdleTimeMillis: 300000
      validationQuery: SELECT 1 FROM DUAL
      #建议配置为true，不影响性能，并且保证安全性。申请连接的时候检测，
      #如果空闲时间大于timeBetweenEvictionRunsMillis，执行validationQuery检测连接是否有效。
      testWhileIdle: true
      #申请连接时执行validationQuery检测连接是否有效，做了这个配置会降低性能。
      testOnBorrow: false
      testOnReturn: false
      # 打开PSCache，并且指定每个连接上PSCache的大小
      poolPreparedStatements: true
      maxPoolPreparedStatementPerConnectionSize: 20
      filter:
        # 配置StatFilter
       stat:
         db-type: h2
         log-slow-sql: true
         slow-sql-millis: 2000
       # 配置WallFilter
       wall:
         enabled: true
         db-type: h2
         config:
           delete-allow: true
           drop-table-allow: false


mybatis:
  config-location: classpath:mybatis/mybatis-config.xml
  mapper-locations: classpath:mybatis/mapper/*.xml

`
}

func LogbackSpring(n string) (string, string) {
	return n + "/src/main/resources/logback-spring.xml", `<?xml version="1.0" encoding="UTF-8"?>
<!-- 日志级别从低到高分为TRACE < DEBUG < INFO < WARN < ERROR < FATAL，如果设置为WARN，则低于WARN的信息都不会输出 -->
<!-- scan:当此属性设置为true时，配置文档如果发生改变，将会被重新加载，默认值为true -->
<!-- scanPeriod:设置监测配置文档是否有修改的时间间隔，如果没有给出时间单位，默认单位是毫秒。
                 当scan为true时，此属性生效。默认的时间间隔为1分钟。 -->
<!-- debug:当此属性设置为true时，将打印出logback内部日志信息，实时查看logback运行状态。默认值为false。 -->
<configuration  scan="true" scanPeriod="10 seconds">
    <contextName>logback</contextName>

    <!-- name的值是变量的名称，value的值时变量定义的值。通过定义的值会被插入到logger上下文中。定义后，可以使“${}”来使用变量。 -->
    <property name="log.path" value="logs" />

    <!--0. 日志格式和颜色渲染 -->
    <!-- 彩色日志依赖的渲染类 -->
    <conversionRule conversionWord="clr" converterClass="org.springframework.boot.logging.logback.ColorConverter" />
    <conversionRule conversionWord="wex" converterClass="org.springframework.boot.logging.logback.WhitespaceThrowableProxyConverter" />
    <conversionRule conversionWord="wEx" converterClass="org.springframework.boot.logging.logback.ExtendedWhitespaceThrowableProxyConverter" />
    <!-- 彩色日志格式 -->
    <property name="CONSOLE_LOG_PATTERN" value="${CONSOLE_LOG_PATTERN:-%clr(%d{yyyy-MM-dd HH:mm:ss.SSS}){faint} %clr(${LOG_LEVEL_PATTERN:-%5p}) %clr(${PID:- }){magenta} %clr(---){faint} %clr([%15.15t]){faint} %clr(%-40.40logger{39}){cyan} %clr(:){faint} %m%n${LOG_EXCEPTION_CONVERSION_WORD:-%wEx}}"/>

    <!--1. 输出到控制台-->
    <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
        <!--此日志appender是为开发使用，只配置最底级别，控制台输出的日志级别是大于或等于此级别的日志信息-->
        <filter class="ch.qos.logback.classic.filter.ThresholdFilter">
            <level>debug</level>
        </filter>
        <encoder>
            <Pattern>${CONSOLE_LOG_PATTERN}</Pattern>
            <!-- 设置字符集 -->
            <charset>UTF-8</charset>
        </encoder>
    </appender>

    <!--2. 输出到文档-->
    <!-- 2.1 level为 DEBUG 日志，时间滚动输出  -->
    <appender name="DEBUG_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <!-- 正在记录的日志文档的路径及文档名 -->
        <file>${log.path}/web_debug.log</file>
        <!--日志文档输出格式-->
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{50} - %msg%n</pattern>
            <charset>UTF-8</charset> <!-- 设置字符集 -->
        </encoder>
        <!-- 日志记录器的滚动策略，按日期，按大小记录 -->
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <!-- 日志归档 -->
            <fileNamePattern>${log.path}/web-debug-%d{yyyy-MM-dd}.%i.log</fileNamePattern>
            <timeBasedFileNamingAndTriggeringPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedFNATP">
                <maxFileSize>100MB</maxFileSize>
            </timeBasedFileNamingAndTriggeringPolicy>
            <!--日志文档保留天数-->
            <maxHistory>15</maxHistory>
        </rollingPolicy>
        <!-- 此日志文档只记录debug级别的 -->
        <filter class="ch.qos.logback.classic.filter.LevelFilter">
            <level>debug</level>
            <onMatch>ACCEPT</onMatch>
            <onMismatch>DENY</onMismatch>
        </filter>
    </appender>

    <!-- 2.2 level为 INFO 日志，时间滚动输出  -->
    <appender name="INFO_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <!-- 正在记录的日志文档的路径及文档名 -->
        <file>${log.path}/web_info.log</file>
        <!--日志文档输出格式-->
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{50} - %msg%n</pattern>
            <charset>UTF-8</charset>
        </encoder>
        <!-- 日志记录器的滚动策略，按日期，按大小记录 -->
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <!-- 每天日志归档路径以及格式 -->
            <fileNamePattern>${log.path}/web-info-%d{yyyy-MM-dd}.%i.log</fileNamePattern>
            <timeBasedFileNamingAndTriggeringPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedFNATP">
                <maxFileSize>100MB</maxFileSize>
            </timeBasedFileNamingAndTriggeringPolicy>
            <!--日志文档保留天数-->
            <maxHistory>15</maxHistory>
        </rollingPolicy>
        <!-- 此日志文档只记录info级别的 -->
        <filter class="ch.qos.logback.classic.filter.LevelFilter">
            <level>info</level>
            <onMatch>ACCEPT</onMatch>
            <onMismatch>DENY</onMismatch>
        </filter>
    </appender>

    <!-- 2.3 level为 WARN 日志，时间滚动输出  -->
    <appender name="WARN_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <!-- 正在记录的日志文档的路径及文档名 -->
        <file>${log.path}/web_warn.log</file>
        <!--日志文档输出格式-->
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{50} - %msg%n</pattern>
            <charset>UTF-8</charset> <!-- 此处设置字符集 -->
        </encoder>
        <!-- 日志记录器的滚动策略，按日期，按大小记录 -->
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>${log.path}/web-warn-%d{yyyy-MM-dd}.%i.log</fileNamePattern>
            <timeBasedFileNamingAndTriggeringPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedFNATP">
                <maxFileSize>100MB</maxFileSize>
            </timeBasedFileNamingAndTriggeringPolicy>
            <!--日志文档保留天数-->
            <maxHistory>15</maxHistory>
        </rollingPolicy>
        <!-- 此日志文档只记录warn级别的 -->
        <filter class="ch.qos.logback.classic.filter.LevelFilter">
            <level>warn</level>
            <onMatch>ACCEPT</onMatch>
            <onMismatch>DENY</onMismatch>
        </filter>
    </appender>

    <!-- 2.4 level为 ERROR 日志，时间滚动输出  -->
    <appender name="ERROR_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <!-- 正在记录的日志文档的路径及文档名 -->
        <file>${log.path}/web_error.log</file>
        <!--日志文档输出格式-->
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{50} - %msg%n</pattern>
            <charset>UTF-8</charset> <!-- 此处设置字符集 -->
        </encoder>
        <!-- 日志记录器的滚动策略，按日期，按大小记录 -->
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>${log.path}/web-error-%d{yyyy-MM-dd}.%i.log</fileNamePattern>
            <timeBasedFileNamingAndTriggeringPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedFNATP">
                <maxFileSize>100MB</maxFileSize>
            </timeBasedFileNamingAndTriggeringPolicy>
            <!--日志文档保留天数-->
            <maxHistory>15</maxHistory>
        </rollingPolicy>
        <!-- 此日志文档只记录ERROR级别的 -->
        <filter class="ch.qos.logback.classic.filter.LevelFilter">
            <level>ERROR</level>
            <onMatch>ACCEPT</onMatch>
            <onMismatch>DENY</onMismatch>
        </filter>
    </appender>

    <!--
        <logger>用来设置某一个包或者具体的某一个类的日志打印级别、
        以及指定<appender>。<logger>仅有一个name属性，
        一个可选的level和一个可选的addtivity属性。
        name:用来指定受此logger约束的某一个包或者具体的某一个类。
        level:用来设置打印级别，大小写无关：TRACE, DEBUG, INFO, WARN, ERROR, ALL 和 OFF，
              还有一个特俗值INHERITED或者同义词NULL，代表强制执行上级的级别。
              如果未设置此属性，那么当前logger将会继承上级的级别。
        addtivity:是否向上级logger传递打印信息。默认是true。
        <logger name="org.springframework.web" level="info"/>
        <logger name="org.springframework.scheduling.annotation.ScheduledAnnotationBeanPostProcessor" level="INFO"/>
    -->

    <!--
        使用mybatis的时候，sql语句是debug下才会打印，而这里我们只配置了info，所以想要查看sql语句的话，有以下两种操作：
        第一种把<root level="info">改成<root level="DEBUG">这样就会打印sql，不过这样日志那边会出现很多其他消息
        第二种就是单独给dao下目录配置debug模式，代码如下，这样配置sql语句会打印，其他还是正常info级别：
        【logging.level.org.mybatis=debug logging.level.dao=debug】
     -->

    <!--
        root节点是必选节点，用来指定最基础的日志输出级别，只有一个level属性
        level:用来设置打印级别，大小写无关：TRACE, DEBUG, INFO, WARN, ERROR, ALL 和 OFF，
        不能设置为INHERITED或者同义词NULL。默认是DEBUG
        可以包含零个或多个元素，标识这个appender将会添加到这个logger。
    -->

    <!-- 4. 最终的策略 -->
    <!-- 4.1 开发环境:打印控制台-->
    <springProfile name="dev">
        <root level="info">
            <appender-ref ref="CONSOLE" />
            <appender-ref ref="DEBUG_FILE" />
            <appender-ref ref="INFO_FILE" />
            <appender-ref ref="WARN_FILE" />
            <appender-ref ref="ERROR_FILE" />
        </root>
    </springProfile>


     <!--4.2 生产环境:输出到文档-->
    <springProfile name="prod">
        <root level="info">
            <appender-ref ref="CONSOLE" />
            <appender-ref ref="INFO_FILE" />
            <appender-ref ref="WARN_FILE" />
            <appender-ref ref="ERROR_FILE" />
        </root>
    </springProfile>

</configuration>

`
}

func Application(n string) (string, string) {

	return n + "/src/main/resources/config/application.yml", `
spring:
  profiles:
    active: dev
  servlet:
    multipart:
      #最大文件大小。值可以使用后缀“MB”或“KB”。指示兆字节或千字节大小。
      max-file-size: 100MB
      # 最大请求大小可以是mb也可以是kb
      max-request-size: 100MB
  banner:
    charset: UTF-8
    location: classpath:static/banner.txt
    resources:
      add-mappings: false
server:
  port: 8086
#  ssl:
#    key-store: classpath:keystore.jks
#    key-store-password: 123456
#    key-password: 123456
#    protocol: TLSv1.2
  http2:
    enabled: true
  use-forward-headers: true



config:
  file-host: localhost
  file-port: 8086
  file-path: img
  file-url: upload
  file-type: java,php,py,go
  authority-init: false


`

}

// Capitalize 字符首字母大写
func Capitalize(str string) string {
	var upperStr string
	vv := []rune(str) // 后文有介绍
	for i := 0; i < len(vv); i++ {
		if i == 0 {
			if vv[i] >= 97 && vv[i] <= 122 { // 后文有介绍
				vv[i] -= 32 // string的码表相差32位
				upperStr += string(vv[i])
			} else {
				fmt.Println("Not begins with lowercase letter,")
				return str
			}
		} else {
			upperStr += string(vv[i])
		}
	}
	return upperStr
}

func TestFile(name, pn, opn string) (string, string) {
	return name + "/src/test/java/" + pn + "/" + Capitalize(name) + "Tests.java", `package ` + opn + `;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class ` + Capitalize(name) + "Tests" + ` {

    @Test
    public void contextLoads() {
    }

}
`

}

func Pom(n, v, opn string) (string, string) {
	return n + "/pom.xml", `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>` + opn + `</groupId>
    <artifactId>` + n + `</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <packaging>jar</packaging>

    <name>` + n + `</name>
    <description>Automatic project for Spring Boot</description>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>` + v + `</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>

    <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
        <java.version>1.8</java.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <exclusions>
                <exclusion>
                    <groupId>org.springframework.boot</groupId>
                    <artifactId>spring-boot-starter-tomcat</artifactId>
                </exclusion>
            </exclusions>
        </dependency>
       <!--注解-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-configuration-processor</artifactId>
            <optional>true</optional>
        </dependency>
       <!--undertow包的依赖-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-undertow</artifactId>
        </dependency>
        <!--jwt-->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.7.0</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-configuration-processor</artifactId>
            <optional>true</optional>
        </dependency>
        <!--mysql驱动包-->
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
        </dependency>
        <!--链接池-->
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>druid-spring-boot-starter</artifactId>
            <version>1.1.10</version>
        </dependency>
        <!--mybatis-->
        <dependency>
            <groupId>org.mybatis.spring.boot</groupId>
            <artifactId>mybatis-spring-boot-starter</artifactId>
            <version>1.3.2</version>
        </dependency>
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.37</version>
        </dependency>
        <!--jpa-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <!--swagger-->
        <dependency>
            <groupId>com.spring4all</groupId>
            <artifactId>swagger-spring-boot-starter</artifactId>
            <version>1.8.0.RELEASE</version>
        </dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
        <!--security-->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-core</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <!--maven 跳过 Test-->
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>2.18.1</version>
                <configuration>
                    <skipTests>true</skipTests>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>
`

}
