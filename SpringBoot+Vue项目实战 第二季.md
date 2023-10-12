# SpringBoot+Vue项目实战 第二季

数据库解释：x_user_role:一个用户可以有哪几种角色

x_role_menu:一个角色可以拥有哪几种权限

x_user_role->x_role_menu找到最后一个用户可以拥有哪几种权限

## 一、些许优化

### 刷新丢失其它标签页

![刷新标签页](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231003170849142.png)

这几个标签页，点击一下刷新，刷新之后其他标签页就不显示了

1. **缓存已打开标签页，在src/layout/components/TagsView/index.vue中进行修改**

   ~~~js
   tagsViewCache() {
       window.addEventListener("beforeunload", () => {
           let tabViews = this.visitedViews.map(item => {
               return {
                   fullPath: item.fullPath,
                   hash: item.hash,
                   meta: { ...item.meta },
                   name: item.name,
                   params: { ...item.params },
                   path: item.path,
                   query: { ...item.query },
                   title: item.title
               };
           });
           sessionStorage.setItem("tabViews", JSON.stringify(tabViews));
       });
       let oldViews = JSON.parse(sessionStorage.getItem("tabViews")) || [];
       if (oldViews.length > 0) {
           this.$store.state.tagsView.visitedViews = oldViews;
       }
   },
   ~~~

   ![image-20230223175152944](md-images/image-20230223175152944.png)



2. **注销时删除所有tagview，修改src/layout/components/Navbar.vue，注意跟上面的内容不在同一个文件**

   ~~~js
   // 注销时删除所有tagview，清除所有的标签页
   await this.$store.dispatch('tagsView/delAllViews')
   sessionStorage.removeItem('tabViews')
   ~~~

   ![image-20230304113637735](md-images/image-20230304113637735.png)

```javascript
async logout() {
  await this.$store.dispatch('user/logout')
  await this.$store.dispatch('tagsView/delAllViews')
  sessionStorage.removeItem('tabViews')
  this.$router.push(`/login`)
}
```

这块如果不修改的话，退出再登录进来会保留之前的标签页

![保留之前的标签页](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231003173035182.png)

这导致了如果普通用户进来，也能看到之前特殊用户能够看到的页面，因此这里我们注销之后只打开首页

## 二、优化token部分

![优化token部分的界面](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231003173333508.png)

目前token没有什么含义，因此这里我们改进，使用jwt去改进我们的uuid

![jwt内容](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231003202705521.png)

jwt中携带了签名信息，具有一定的安全性(见后面的Jwt整合部分)

## 三、Swagger整合

Swagger-UI可以动态地根据注解生成在线API文档。

**常用注解**

- @Api：用于修饰Controller类，生成Controller相关文档信息
- @ApiOperation：用于修饰Controller类中的方法，生成接口方法相关文档信息
- @ApiParam：用于修饰接口中的参数，生成接口参数相关文档信息
- @ApiModelProperty：用于修饰实体类的属性，当实体类是请求参数或返回结果时，直接生成相关文档信息



**整合步骤：**

1. 添加依赖，放在根的pom.xml中

   ~~~xml
   <!--Swagger文档工具-->
   <dependency>
       <groupId>io.springfox</groupId>
       <artifactId>springfox-boot-starter</artifactId>
       <version>3.0.0</version>
   </dependency>
   ~~~

2. swagger配置类

   放在src/main/java/com.lantu.config.MySwaggerConfig中

   ~~~java
   @Configuration
   @EnableOpenApi
   @EnableWebMvc
   public class SwaggerConfig {
       @Bean
       public Docket api() {
           return new Docket(DocumentationType.OAS_30)
                   .apiInfo(apiInfo())
                   .select()
                   .apis(RequestHandlerSelectors.basePackage("com.lantu"))
                   .paths(PathSelectors.any())
                   .build();
       }
   
       private ApiInfo apiInfo() {
           return new ApiInfoBuilder()
                   .title("神盾局特工管理系统接口文档")
                   .description("全网最简单的SpringBoot+Vue前后端分离项目实战")
                   .version("1.0")
                   .contact(new Contact("qqcn", "http://www.qqcn.cn", "qqcn@aliyun.com"))
                   .build();
       }
   }
   ~~~

3. 控制器根据需要添加swagger注解

   注意这里的Contact导入springfox

   ![导入springfox](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231004090128050.png)

   注意这里的包名需要修改一下

   ![修改一下包名](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231004090228267.png)

4. 测试：http://localhost:9999/swagger-ui/index.html

测试的时候需要把MyCorsConfig这个拦截器上面的注解@Configuration去除掉，然后打开http://localhost:9999/swagger-ui/index.html#/

![接口文档](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231004090639909.png)

![接口描述](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231004090737077.png)

上面加入用户接口列表以及用户登录接口的说明

![用户接口列表](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231004091238664.png)

![用户登录接口](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231004091308732.png)

打开swagger之后会有对应的提示

![swagger对应的提示](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231004091344140.png)

打开接口之后点击try it out可以进行测试

**注意这里拦截器需要放行，否则swagger无法打开界面，在MyWebConfig中**

```java
@Configuration
public class MyWebConfig implements WebMvcConfigurer {
    @Autowired
    private JwtValidateInterceptor jwtValidateInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        //可以点右键->generate
        InterceptorRegistration registration = registry.addInterceptor(jwtValidateInterceptor);
        registration.addPathPatterns("/**")
                //拦截所有资源
                .excludePathPatterns(
                        "/user/login",
                        "/user/info",
                        "/user/logout",
                        "/error",
                        "/swagger-ui/**",
                        "/swagger-resources/**",
                        "/v3/**");
        //放行登录等接口
    }
}
```

## 三、Jwt整合

JSON Web Token (JWT)是一个开放标准(RFC 7519)，它定义了一种紧凑的、自包含的方式，用于作为JSON对象在各方之间安全地传输信息。该信息可以被验证和信任，因为它是数字签名的。

**jwt形式举例：**

~~~
eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI5MjAzOThjZi1hYThiLTQzNWUtOTIxYS1iNGQ3MDNmYmZiZGQiLCJzdWIiOiJ7XCJwaG9uZVwiOlwiMTIzNDIzNFwiLFwidXNlcm5hbWVcIjpcInpoYW5nc2FuXCJ9IiwiaXNzIjoic3lzdGVtIiwiaWF0IjoxNjc3MTE4Njc2LCJleHAiOjE2NzcxMjA0NzZ9.acc7H6-6ACqcgNu5waqain7th7zJciP-41z-qgWeaSY
~~~



### ⑴ 整合步骤

1. pom

   ~~~xml
   <dependency>
       <groupId>io.jsonwebtoken</groupId>
       <artifactId>jjwt</artifactId>
       <version>0.9.1</version>
   </dependency>
   ~~~

2. 工具类，放在com.lantu.common.utils.JwtUtil的文件中

   ~~~java
   @Component
   public class JwtUtil {
       // 有效期
       private static final long JWT_EXPIRE = 30*60*1000L;  //半小时
       // 令牌秘钥
       private static final String JWT_KEY = "123456";
   
       public  String createToken(Object data){
           // 当前时间
           long currentTime = System.currentTimeMillis();
           // 过期时间
           long expTime = currentTime+JWT_EXPIRE;
           // 构建jwt
           JwtBuilder builder = Jwts.builder()
                   .setId(UUID.randomUUID()+"")
                   .setSubject(JSON.toJSONString(data))
                   .setIssuer("system")
                   .setIssuedAt(new Date(currentTime))
                   .signWith(SignatureAlgorithm.HS256, encodeSecret(JWT_KEY))
             			//签名的密钥针对123456进行加密处理
             			//这里采用HS256加密算法，更安全可以采用非对称加密
                   .setExpiration(new Date(expTime));
           return builder.compact();
       }
   
       private  SecretKey encodeSecret(String key){
           byte[] encode = Base64.getEncoder().encode(key.getBytes());
           SecretKeySpec aes = new SecretKeySpec(encode, 0, encode.length, "AES");
           return  aes;
       }
   
       public  Claims parseToken(String token){
           Claims body = Jwts.parser()
                   .setSigningKey(encodeSecret(JWT_KEY))
                   .parseClaimsJws(token)
                   .getBody();
           return body;
       }
   
       public <T> T parseToken(String token,Class<T> clazz){
           Claims body = Jwts.parser()
                   .setSigningKey(encodeSecret(JWT_KEY))
                   .parseClaimsJws(token)
                   .getBody();
           return JSON.parseObject(body.getSubject(),clazz);
       }
   
   }
   ~~~

3. 测试工具类

   这里的测试类需要在test文件夹下面测试

   ```java
   @SpringBootTest(classes = {XAdminApplication.class})
   //报错java.lang.IllegalStateException: Unable to find a @SpringBootConfiguration, you need to use @ContextConfiguration or @SpringBootTest(classes=...) with your test
   //需要加上类的注解
   public class JwtUtilTest {
       @Autowired
       private JwtUtil jwtUtil;
   
       @Test
       public void testCreateJwt(){
           User user = new User();
           user.setUsername("zhangsan");
           user.setPhone("12399988877");
           String token = jwtUtil.createToken(user);
           System.out.println(token);
       }
   
       @Test
       public void testParseJwt(){
           String token = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJmMTI3ZDA4Mi03OGY4LTQ5ZTMtOThhMS05NmM5NTUxYTNkYjEiLCJzdWIiOiJ7XCJwaG9uZVwiOlwiMTIzOTk5ODg4NzdcIixcInVzZXJuYW1lXCI6XCJ6aGFuZ3NhblwifSIsImlzcyI6InN5c3RlbSIsImlhdCI6MTY5NjMzODg3MSwiZXhwIjoxNjk2MzQwNjcxfQ.Pg0qCAnL5fYS2tZGrs_BWHFq8LsgsdKrtfogLsPAwVE";
           Claims claims = jwtUtil.parseToken(token);
           System.out.println(claims);
       }
   }
   ```

   

4. 修改登录逻辑

   把

   ```java
   redisTemplate.opsForValue().set(key,loginUser,30, TimeUnit.MINUTES);
   ```

   给注释掉，然后注入Jwt，并且创建之后放入data中

   ![image-20230223144308843](md-images/image-20230223144308843.png)

   然后这里将从redis中拿出数据的部分注释掉

   ```java
   //Object obj = redisTemplate.opsForValue().get(token);
   
   并且之前从redis中反序列化处理的代码也不需要了
   //User loginUser = JSON.parseObject(JSON.toJSONString(obj),User.class);
   ```

   

   ![image-20230223145139765](md-images/image-20230223145139765.png)

   ![image-20230223145717367](md-images/image-20230223145717367.png)

   注销的时候也不需要删除了，直接注释掉

5. 测试登录

重新登录之后可以看到存在cookie

![cookie的截图内容](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231003214448278.png)

**问题思考：**

登录后续请求如何验证jwt ？

![image-20230223151911140](md-images/image-20230223151911140.png)

前端后续所有的请求都需要携带JWT，后端通过前端的JWT信息来判断前端的权限，目前存在的问题为无效的token也能够登录

### ⑵ JWT验证拦截器

定义拦截器，在com.lantu.interceptor.JwtValidateInterceptor.java中定义

~~~java
@Component
@Slf4j
public class JwtValidateInterceptor implements HandlerInterceptor {
    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String token = request.getHeader("X-Token");
        //想办法从请求头中获取token
        System.out.println(request.getRequestURI() +" 待验证："+token);
        if(token != null){
            try {
                jwtUtil.parseToken(token);
                log.debug(request.getRequestURI() + " 验证通过");
                //如果走到log.debug就说明成功运行了，开发中使用System.out
                //会影响性能
                return true;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        log.debug(request.getRequestURI() + " 验证失败，禁止访问...");
        response.setContentType("application/json;charset=utf-8");
        //验证失败的时候，需要以json形式返回信息
   response.getWriter().write(JSON.toJSONString(Result.fail(20003,"jwt令牌无效，请重新登录")));
        return false;  //拦截
    }
}
~~~

注册拦截器，在config/MyWebConfig中定义

~~~java
@Configuration
public class MyWebConfig implements WebMvcConfigurer {
    @Autowired
    private JwtValidateInterceptor jwtValidateInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        //可以点右键->generate
        InterceptorRegistration registration = registry.addInterceptor(jwtValidateInterceptor);
        registration.addPathPatterns("/**")
          //拦截所有资源
                .excludePathPatterns(
                        "/user/login",
                        "/user/info",
                        "/user/logout",
                        "/error",
                        "/swagger-ui/**",
                        "/swagger-resources/**",
                        "/v3/**");
      	//放行登录等接口
    }
}
~~~

修改了Value值之后会显示错误如下

![修改Value值显示的错误](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231003231237387.png)

这就说明jwt的token拦截成功了

### ⑶ Swagger授权配置

~~~java
@Configuration
@EnableOpenApi
@EnableWebMvc
public class SwaggerConfig {
    @Bean
    public Docket api() {
        return new Docket(DocumentationType.OAS_30)
                .apiInfo(apiInfo())
                .select()
                .apis(RequestHandlerSelectors.basePackage("com.lantu"))
                .paths(PathSelectors.any())
                .build()
                
         //下面两句属于swagger认证代码 
          .securitySchemes(Collections.singletonList(securityScheme()))
                .securityContexts(Collections.singletonList(securityContext()));
    }
	
  	//下面的部分属于swagger认证代码，注意这里都导入springfox这个包里面的类
    private SecurityScheme securityScheme() {
        //return new ApiKey("Authorization", "Authorization", "header");
        return new ApiKey("X-Token", "X-Token", "header");
    }

    private SecurityContext securityContext() {
        return SecurityContext.builder()
                .securityReferences(defaultAuth())
                .forPaths(PathSelectors.regex("^(?!auth).*$"))
                .build();
    }

    private List<SecurityReference> defaultAuth() {
        AuthorizationScope authorizationScope = new AuthorizationScope("global", "accessEverything");
        AuthorizationScope[] authorizationScopes = new AuthorizationScope[1];
        authorizationScopes[0] = authorizationScope;
        return Collections.singletonList(
                new SecurityReference("X-Token", authorizationScopes));
    }
  	//上面这段属于swagger认证代码，注意都选择导入springfox包里面的类

    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("神盾局特工管理系统接口文档")
                .description("全网最简单的SpringBoot+Vue前后端分离项目实战")
                .version("1.0")
                .contact(new Contact("老蔡", "https://space.bilibili.com/431588578", "xxxx@aliyun.com"))
                .build();
    }
}
~~~

## 四、角色管理

### 1. 基本功能

#### ⑴ 预览效果

![image-20230223165130923](md-images/image-20230223165130923.png)

**这里参照之前user.vue代码自己去写**

#### ⑵ 前端

把之前的user.vue中的代码粘贴到role.vue中

角色字段查看数据库中的数据

![数据库中的角色字段](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231004112625823.png)

**目前这里没有deleted，因此会直接删除，想要逻辑删除我们需要加上deleted这个字段**

role.vue

~~~vue
<template>
  <div>
    <!-- 搜索栏 -->
    <el-card id="search">
      <el-row>
        <el-col :span="18">
          <el-input placeholder="角色名" v-model="searchModel.roleName" clearable> </el-input>
          <el-button @click="getRoleList" type="primary" icon="el-icon-search" round>查询</el-button>
        </el-col>
        <el-col :span="6" align="right">
          <el-button @click="openEditUI(null)" type="primary" icon="el-icon-plus" circle></el-button>
        </el-col>
      </el-row>
    </el-card>

    <!-- 结果列表 -->
    <el-card>
 
        <el-table :data="roleList" stripe style="width: 100%">
          <el-table-column label="#" width="80">
            <template slot-scope="scope">
              {{(searchModel.pageNo-1) * searchModel.pageSize + scope.$index + 1}}
            </template>
          </el-table-column>
          <el-table-column prop="roleId" label="角色编号" width="180">
          </el-table-column>
          <el-table-column prop="roleName" label="角色名称" width="180">
          </el-table-column>
          <el-table-column prop="roleDesc" label="角色描述" >
          </el-table-column>
          <el-table-column   label="操作" width="180">
            <template slot-scope="scope">
              <el-button @click="openEditUI(scope.row.roleId)" type="primary" icon="el-icon-edit" circle size="mini"></el-button>
              <el-button @click="deleteRole(scope.row)" type="danger" icon="el-icon-delete" circle size="mini"></el-button>
            </template>
          </el-table-column>
        </el-table> 
 
    </el-card>
    <el-pagination
      @size-change="handleSizeChange"
      @current-change="handleCurrentChange"
      :current-page="searchModel.pageNo"
      :page-sizes="[5, 10, 20, 50]"
      :page-size="searchModel.pageSize"
      layout="total, sizes, prev, pager, next, jumper"
      :total="total">
    </el-pagination>

    <!-- 对话框 -->
    <el-dialog @close="clearForm" :title="title" :visible.sync="dialogFormVisible" :close-on-click-modal="false">
      <el-form :model="roleForm" ref="roleFormRef" :rules="rules">
        <el-form-item prop="roleName" label="角色名称" :label-width="formLabelWidth">
          <el-input v-model="roleForm.roleName" autocomplete="off"></el-input>
        </el-form-item>
        
        <el-form-item prop="roleDesc" label="角色描述" :label-width="formLabelWidth">
          <el-input v-model="roleForm.roleDesc" autocomplete="off"></el-input>
        </el-form-item>
      </el-form>
      <div slot="footer" class="dialog-footer">
        <el-button @click="dialogFormVisible = false">取 消</el-button>
        <el-button type="primary" @click="saveRole">确 定</el-button>
      </div>
    </el-dialog>
  </div>
</template>


<script>
import roleApi from '@/api/roleManage'
export default {
  data(){
    
    return{
      formLabelWidth: '130px',
      roleForm: {},
      dialogFormVisible: false,
      title: '',
      searchModel: {
        pageNo: 1,
        pageSize: 10
      },
      roleList: [],
      total: 0,
      rules:{
        roleName: [
          { required: true, message: '请输入角色名称', trigger: 'blur' },
          { min: 3, max: 50, message: '长度在 3 到 50 个字符', trigger: 'blur' }
        ]
      }
    }
  },
  methods:{
    deleteRole(role){
      this.$confirm(`您确定删除角色 ${role.roleName} ？`, '提示', {
          confirmButtonText: '确定',
          cancelButtonText: '取消',
          type: 'warning'
      }).then(() => {
        roleApi.deleteRoleById(role.roleId).then(response => {
          this.$message({
            type: 'success',
            message: response.message
          });
          this.dialogFormVisible = false;
          this.getRoleList();
        });
        
      }).catch(() => {
        this.$message({
          type: 'info',
          message: '已取消删除'
        });          
      });
    },
    saveRole(){
      // 触发表单验证
      this.$refs.roleFormRef.validate((valid) => {
        if (valid) {
          // 提交保存请求
          roleApi.saveRole(this.roleForm).then(response => {
            // 成功提示
            this.$message({
              message: response.message,
              type: 'success'
            });
            // 关闭对话框
            this.dialogFormVisible = false;
            // 刷新表格数据
            this.getRoleList();
          });
          
        } else {
          console.log('error submit!!');
          return false;
        }
      });
      
    },
    clearForm(){
      this.roleForm = {};
      this.$refs.roleFormRef.clearValidate();
    },
    openEditUI(id){
      if(id == null){
        this.title = '新增角色';
      }else{
        this.title = '修改角色';
        roleApi.getRoleById(id).then(response => {
          this.roleForm = response.data;
        });
      }
      this.dialogFormVisible = true;
    },
    handleSizeChange(pageSize){
      this.searchModel.pageSize = pageSize;
      this.getRoleList();
    },
    handleCurrentChange(pageNo){
      this.searchModel.pageNo = pageNo;
      this.getRoleList();
    },
    getRoleList(){
      roleApi.getRoleList(this.searchModel).then(response => {
        this.roleList = response.data.rows;
        this.total = response.data.total;
      });
    }
  },
  created(){
    this.getRoleList();
  }
};
</script>

<style>
#search .el-input {
  width: 200px;
  margin-right: 10px;
}
.el-dialog .el-input{
  width: 85%;
}
</style>
~~~

roleManage.js

~~~js
import request from '@/utils/request'

export default{
  // 分页查询角色列表
  getRoleList(searchModel){
    return request({
      url: '/role/list',
      method: 'get',
      params: {
        roleName: searchModel.roleName,
        pageNo: searchModel.pageNo,
        pageSize: searchModel.pageSize
      }
    });
  },
  // 新增
  addRole(role){
    return request({
      url: '/role',
      method: 'post',
      data: role
    });
  },
  // 修改
  updateRole(role){
    return request({
      url: '/role',
      method: 'put',
      data: role
    });
  },
  // 保存角色数据
  saveRole(role){
    if(role.roleId == null || role.roleId == undefined){
      return this.addRole(role);
    }
    return this.updateRole(role);
  },
  // 根据id查询
  getRoleById(id){
    return request({
      url: `/role/${id}`,
      method: 'get'
    });
  },
  // 根据id删除
  deleteRoleById(id){
    return request({
      url: `/role/${id}`,
      method: 'delete'
    });
  },

}
~~~



#### ⑶ 后端

RoleController

~~~java
@RestController
@RequestMapping("/role")
public class RoleController {

    @Autowired
    private IRoleService roleService;

    @GetMapping("/list")
    public Result<Map<String,Object>> getUserList(@RequestParam(value = "roleName",required = false) String roleName,
                                                  @RequestParam(value = "pageNo") Long pageNo,
                                                  @RequestParam(value = "pageSize") Long pageSize){
        LambdaQueryWrapper<Role> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(StringUtils.hasLength(roleName),Role::getRoleName,roleName);
        wrapper.orderByDesc(Role::getRoleId);

        Page<Role> page = new Page<>(pageNo,pageSize);
        roleService.page(page, wrapper);

        Map<String,Object> data = new HashMap<>();
        data.put("total",page.getTotal());
        data.put("rows",page.getRecords());

        return Result.success(data);

    }

    @PostMapping
    public Result<?> addRole(@RequestBody Role role){
        roleService.save(role);
        return Result.success("新增角色成功");
    }

    @PutMapping
    public Result<?> updateRole(@RequestBody Role role){
        roleService.updateById(role);
        return Result.success("修改角色成功");
    }

    @GetMapping("/{id}")
    public Result<Role> getRoleById(@PathVariable("id") Integer id){
        Role role = roleService.getById(id);
        return Result.success(role);
    }

    @DeleteMapping("/{id}")
    public Result<Role> deleteRoleById(@PathVariable("id") Integer id){
        roleService.removeById(id);
        return Result.success("删除角色成功");
    }

}
~~~

**注意：1.这里如果无法进行逻辑删除，查看Role这个类是否定义了deleted这个属性。2.如果插入值的时候deleted默认值为null，需要定义deleted的默认值：alter table x_role modify column deleted int default 0;3.如果没输入的时候，对话框没有出现应该有的提示内容，重启浏览器可解决**

### 2. 角色权限设置显示

![image-20230224143515265](md-images/image-20230224143515265.png)



#### ⑴ 前端

menuManage.js

~~~js
import request from '@/utils/request'

export default{
  // 查询所有菜单数据
  getAllMenu(){
    return request({
      url: '/menu',
      method: 'get',
    });
  },
}
~~~

role.vue，在el-form-item下面加入内容

~~~html
<el-form-item
              prop="roleDesc"
              label="权限设置"
              :label-width="formLabelWidth"
              >
    <el-tree
             :data="menuList"
             :props="menuProps"
             node-key="menuId"
             show-checkbox
             style="width:85%"
             default-expand-all
             ></el-tree>
</el-form-item>
~~~

完整的el-form部分的定义

```javascript
<el-form :model="roleForm" ref="roleFormRef" :rules="rules">
  <el-form-item label="角色名称" prop="roleName" :label-width="formLabelWidth">
    <!--label-width指的是到左边框的宽度，v-model为绑定的变量-->
    <el-input v-model="roleForm.roleName" autocomplete="off"></el-input>
  </el-form-item>
  <el-form-item label="角色描述" prop="roleDesc" :label-width="formLabelWidth">
      <!--label-width指的是到左边框的宽度，v-model为绑定的变量-->
      <el-input v-model="roleForm.roleDesc" autocomplete="off"></el-input>
  </el-form-item>
  <el-form-item label="权限设置" prop="menuIdList" :label-width="formLabelWidth"></el-form-item>
  <!--这里加入树形控件，注意上面选中之后只需要menuId，而下面需要menuList的数据集合-->
  <el-tree :data="menuList" :props="menuProps" show-checkbox></el-tree>
</el-form>
```

然后补充下面的数据

<img src="md-images/image-20230224143308759.png" alt="image-20230224143308759" style="zoom:80%;" />

这里的label需要控制左侧的菜单项可以动态地展示

![左侧菜单栏](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231006154318139.png)

正好数据库中的title就是我们需要展示的，

![数据库中的title](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231006154551498.png)

因此这里的label中我们填'title'

接下来在src/api/menuManager.js中定义方法

![菜单定义](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231006154916201.png)

然后引用一下menuApi

```javascript
import menuApi from '@/api/menuManager'
```

接下来在src/api/views/sys/role.vue中的methods定义getAllMenu方法

```javascript
methods:{
    getAllMenu(){
      menuApi.getAllMenu().then(response => {
        this.menuList = response.data;
      });
    },
```

在src/views/sys/role.vue中created导入src/api/menuManager.js中定义的getAllMenu()方法

![image-20231006155628675](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231006155628675.png)

**这里的数据需要动态地展示，因此需要从数据表中取出**

数据来源于菜单表，菜单表由路由数据配置而来的，在src/router/index.js中可以进行查看路由的配置

![路由配置内容](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231006160350210.png)

#### ⑵ 数据库

x_menu表新增数据，这个表实际根据src/router/index.js中的路由配置设计出来的

~~~sql
delete from x_menu;
insert into `x_menu` (`menu_id`, `component`, `path`, `redirect`, `name`, `title`, `icon`, `parent_id`, `is_leaf`, `hidden`) values('1','Layout','/sys','/sys/user','sysManage','系统管理','userManage','0','N','0');
insert into `x_menu` (`menu_id`, `component`, `path`, `redirect`, `name`, `title`, `icon`, `parent_id`, `is_leaf`, `hidden`) values('2','sys/user','user',NULL,'userList','用户列表','user','1','Y','0');
insert into `x_menu` (`menu_id`, `component`, `path`, `redirect`, `name`, `title`, `icon`, `parent_id`, `is_leaf`, `hidden`) values('3','sys/role','role',NULL,'roleList','角色列表','roleManage','1','Y','0');
insert into `x_menu` (`menu_id`, `component`, `path`, `redirect`, `name`, `title`, `icon`, `parent_id`, `is_leaf`, `hidden`) values('4','Layout','/test','/test/test1','test','功能测试','form','0','N','0');
insert into `x_menu` (`menu_id`, `component`, `path`, `redirect`, `name`, `title`, `icon`, `parent_id`, `is_leaf`, `hidden`) values('5','test/test1','test1','','test1','测试点一','form','4','Y','0');
insert into `x_menu` (`menu_id`, `component`, `path`, `redirect`, `name`, `title`, `icon`, `parent_id`, `is_leaf`, `hidden`) values('6','test/test2','test2','','test2','测试点二','form','4','Y','0');
insert into `x_menu` (`menu_id`, `component`, `path`, `redirect`, `name`, `title`, `icon`, `parent_id`, `is_leaf`, `hidden`) values('7','test/test3','test3','','test3','测试点三','form','4','Y','0');
~~~

![修改之后的数据库数据](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231006164334001.png)

#### ⑶ 后端

首先修改一下Menu.java文件，get和set方法直接使用lombok的@Data进行生成

Menu.java类中在下面继续加入内容

~~~java
@TableField(exist = false)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
//子菜单中的子菜单可能没有children类型，如果返回null前端显示可能存在问题
private List<Menu> children;

@TableField(exist = false)
private Map<String,Object> meta = new HashMap<>();
public Map<String,Object> getMeta(){
    meta.put("title",this.title);
    meta.put("icon",this.icon);
    return this.meta;
}
~~~

依据

![路由配置内容](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231006160350210.png)

中显示的内容获取

MenuController

~~~~java
@RestController
@RequestMapping("/menu")
public class MenuController {
    @Autowired
    private IMenuService menuService;

    @GetMapping
    public Result<?> getAllMenu(){
        List<Menu> menuList =  menuService.getAllMenu();
        //注意这里MenuServiceImpl下面实现了方法之后才不会报错
        return Result.success(menuList);
    }

}
~~~~

MenuSeviceImpl

~~~java
@Override
public List<Menu> getAllMenu() {
    // 一级菜单
    LambdaQueryWrapper<Menu> wrapper = new LambdaQueryWrapper();
    wrapper.eq(Menu::getParentId,0);
    List<Menu> menuList = this.list(wrapper);
    // 子菜单
    setMenuChildren(menuList);
    return menuList;
}

private void setMenuChildren(List<Menu> menuList) {
    if(menuList != null) {
      //递归退出的条件
      for (Menu menu:menuList) {
          LambdaQueryWrapper<Menu> subWrapper = new LambdaQueryWrapper();
          subWrapper.eq(Menu::getParentId, menu.getMenuId());
          //查阅当前的Menu节点谁把它当作父节点
          List<Menu> subMenuList = this.list(subWrapper);
          menu.setChildren(subMenuList);
          // 递归，当前层处理完了，继续递归处理当前层的孩子层
          setMenuChildren(subMenuList);
      }
    }
}
~~~

这里测试的时候使用postman发送请求，先调用login获取token值，然后在header中加入X-Token进行调用

这里el-tree的width可以设定为85%

```html
<el-tree :data="menuList" :props="menuProps" show-checkbox default-expand-all style="width:85%"></el-tree>
```

default-expand-all为默认全部展开

### 3. 角色权限新增提交

#### ⑴ 前端

**需要解决的问题：勾选的数据如何拿到？提交到后端之后写到哪张表里面？**

1.勾选数据使用node-key进行标识

node-key="menuId"

![image-20230224152419150](md-images/image-20230224152419150.png)

！！！注意这里一定要设置node-key属性，否则调用getCheckedNodes、getCheckedKeys,setCheckedNodes、setCheckedKeys都会报错：

"Error: [Tree] nodeKey is required in setCheckedKeys"

选中节点之后使用getCheckedKeys调用选择中的内容



#### 1.< el-form-item label="权限设置" prop="menuIdList" :label-width="formLabelWidth" >解释

**这里的prop="menuIdList指的是可以通过"**

#### 2.下面代码解释

```html
<el-tree :data="menuList" 
  :props="menuProps" 
  show-checkbox
  node-key="menuId" 
  default-expand-all
  ref="menuRef" 
  style="85%">
</el-tree>
```

menuList为上面传入的值，menuProps定义为

menuProps: {

​      children: 'children',

​      label: 'title',
},

这个是显示的规则，children为Menu中继续展开的children属性，label为显示的内容，显示Menu的title，

node-key="menuId"为getSelectedKeys()返回的值，这里返回Menu的menuId，ref为调用这个组件需要用到的内容，调用的时候this.$refs.menuRef.getCheckedKeys(...)

**注意这里的属性都是后端定义的对应数据库的变量**

![选中的内容](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231006203023136.png)

这里的getCheckedKeys()返回的是被选变量组成的数组，比如这样

![选中的情况](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231006203430778.png)

返回的数组为[2,5,6]，这只是全选中，还需要获取半选中的节点，即系统管理和功能管理

全选中就是选中状态

![全选中的状态](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231006203657302.png)

![image-20230224152450377](md-images/image-20230224152450377.png)

![选中的数据](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231006204002001.png)

比如上面这样选中之后，返回[2,5,6,1,4]这个数组

#### ⑵ 后端

这里需要加入@TableField(exist = false)的原因在于addRole的时候接受参数以Role形式接收，因此必须要有Role这个参数

```java
@PostMapping
public Result<?> addRole(@RequestBody Role role){
  ......
}
```



![image-20230224152549889](md-images/image-20230224152549889.png)

这里需要干两件事：1.写入角色表x_role(定义角色名称和角色id)。2.写入角色和菜单的对照表x_role_menu(定义角色和菜单的对应关系，即该角色能打开哪几个菜单)。

这里设计的这两个操作直接在后端的同一个接口完成，而不是分别去请求两个接口

也可以设计成像登录那样发出两次请求，登录请求如下：

```javascript
this.saveUser(this.userForm).then(response => {
  // 成功提示，需要关闭对话框，并且刷新表格
  this.$message({
    message: response.message,
    type: 'success'
  });
})};
//关闭对话框
this.dialogFormVisible = false;
//刷新表格
this.getUserList();
```

接下来这里首先定义接口

```java
@PostMapping
public Result<?> addRole(@RequestBody Role role){
    //使用@RequestBody的原因是前端传过来的是一个json数据
    System.out.println("role.tostring = ");
    System.out.println(role.toString());
    roleService.addRole(role);
    return Result.success("新增角色成功");
}
```



![image-20230224152636154](md-images/image-20230224152636154.png)

如果这里@Autowired出现问题可以换成@Resource，实际上@Autowired也可以使用，@Autowired在编译阶段不再会去找

**注意这里接口有多个动作，需要加入@Transactional，之前不需要加入@Transactional的原因在于之前只是取数，没有修改数据库，而这里修改数据库了，修改数据库的动作必须一气呵成**

写到数据库之中的数据库数值如下所示：

![写入到数据库的数值](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231008170406138.png)

![mapper文件夹](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231008170701118.png)

mapper中定义了sql的方法，这些可以使用java方法直接调用，而

![service的各种图片](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231008170757455.png)

service定义了各种接口，这些接口需要调用impl方法实现

![调用impl方法实现](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231008170840671.png)

### 4. 角色权限回显(可自主完成)

点修改的时候这里的权限设置没有回显，这里我们需要修改一下前端让数据能够回显

![数据无法回显](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231008171217041.png)

#### ⑴ 前端

![image-20230224203624584](md-images/image-20230224203624584.png)

#### ⑵ 后端

![image-20230224203728968](md-images/image-20230224203728968.png)

**我的疏漏在于没有想到使用role.setMenuIdList将查询的结果包装起来，直接返回List< Integer >返回值为1，2，3导致前端接收到的结果错乱**

**这里后端返回的数据**

![image-20231009142605485](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231009142605485.png)

此时只需要把menuIdList直接赋值给前端的界面即可

```javascript
this.$refs.menuRef.setCheckedKeys(response.data.menuIdList);
```

![image-20230224203755060](md-images/image-20230224203755060.png)

RoleMenuMapper.xml

**我的疏漏为这里忘记连一张表了，这里需要判读is_leaf是否为Yes这里我忘记了，导致忘连一张表**

~~~xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.lantu.sys.mapper.RoleMenuMapper">
    <select id="getMenuIdListByRoleId" parameterType="Integer" resultType="Integer">
        select
            a.`menu_id`
        from x_role_menu a, x_menu b
        where a.`menu_id` = b.`menu_id`
          and b.`is_leaf` = 'Y'
          and a.`role_id` = #{roleId}
    </select>
</mapper>
~~~



### 5. 角色权限修改提交

这里官方调用的是修改

```java
@PutMapping
public Result<?> updateRole(@RequestBody Role role){
    roleService.updateRole(role);
    return Result.success("修改角色成功");
}
```

中的roleService.updateRole方法实现，增删改使用了类似于

```java
LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();       wrapper.eq(StringUtils.hasLength(username),User::getUsername,username);
wrapper.eq(StringUtils.hasLength(phone),User::getPhone,phone);
wrapper.orderByDesc(User::getId);
```

的这种方法，自己实现一下

#### ⑴ 后端

RoleServiceImpl新增

~~~java
@Override
@Transactional
public void updateRole(Role role) {
    // 更新role表
    this.updateById(role);
    // 清除原有权限
    LambdaQueryWrapper<RoleMenu> wrapper = new LambdaQueryWrapper<>();
    wrapper.eq(RoleMenu::getRoleId,role.getRoleId());
    roleMenuMapper.delete(wrapper);
    //新增权限
    for (Integer menuId : role.getMenuIdList()) {
        roleMenuMapper.insert(new RoleMenu(null,role.getRoleId(),menuId));
    }
}
~~~



### 6. 角色删除时删相关权限

删除x_role以及删除x_role_menu中的相关项

#### ⑴ 后端

![image-20230227092921027](md-images/image-20230227092921027.png)





## 五、用户角色设置(跟上面的角色管理类似，可自主完成)

这里从数据库读取列表选项我想错了，不是点开增加或者修改用户按钮之后再进行查询，而是刚开始就进行查询并且保存成变量，点开之后直接就显示出来了，按修改用户按钮的时候需要能够查询当前用户的所属角色

### 1. 角色展示

#### ⑴ 前端

roleManage.js

~~~js
// 查询所有角色列表
getAllRole(){
    return request({
        url: '/role/all',
        method: 'get'
    });
},
~~~

user.vue

![image-20230227084818220](md-images/image-20230227084818220.png)

![image-20230226200016264](md-images/image-20230226200016264.png)

![image-20230225234159510](md-images/image-20230225234159510.png)

![image-20230226200129342](md-images/image-20230226200129342.png)



#### ⑵ 后端

RoleController

![image-20230225235143206](md-images/image-20230225235143206.png)



### 2. 新增用户时提交角色

#### ⑴ 后端

![image-20230227082702204](md-images/image-20230227082702204.png)

UserServiceImpl

![image-20230227082720959](md-images/image-20230227082720959.png)



### 3. 角色回显

#### ⑴ 后端

UserServiceImpl

![image-20230227090743084](md-images/image-20230227090743084.png)



### 4. 修改用户时提交角色

#### ⑴ 后端

UserServiceImpl

![image-20230227093652795](md-images/image-20230227093652795.png)



### 5. 用户删除时删相关角色

#### ⑴ 后端

UserServiceImpl

![image-20230227093715114](md-images/image-20230227093715114.png)

**x_role_menu，x_user_role如果想要使用逻辑删除的话，必须要修改逻辑，否则会有bug，比如先逻辑删除的时候deleted修改为了1，然后重新插入的时候又出现了新的deleted为0的数值，等于deleted=0跟deleted=1在数据库中同时存在!!!**

还需要修改一个新增用户的接口，先学动态路由，学完再来改

## 六、动态路由(根据不同用户权限的不同选择不同的显示方式)--这一块作者讲的不是很清楚，不学也罢

![登录之后，左边栏根据用户权限的不同，动态地展示出来](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231010163126947.png)

### 1.修改getUserInfo接口，根据用户权限的不同返回不同

###  根据用户查询菜单

#### ⑴ 后端

MenuMapper.xml

~~~xml
<select id="getMenuListByUserId" resultType="Menu">
    SELECT 
  		distinct a.*
    FROM x_menu a,
    x_role_menu b,
    x_user_role c
    WHERE a.`menu_id` = b.`menu_id`
    AND b.`role_id` = c.`role_id`
    AND a.`parent_id` = #{pid}
    AND c.`user_id` = #{userId}
</select>
~~~

使用distinct防止路由重复，比如出现多个功能测试的模块

**这里Menu使用的是别名，因此需要在yml文件中配置**

yml

~~~yaml
type-aliases-package: com.lantu.*.entity
~~~

**注意这里需要改成自己的entity路径，否则会报错：**

```
```



这里配置在mybatis-plus下面配置

![mybatis-plus配置](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231010164846436.png)

这样mybatis-plus就会自动扫描对应的包

MenuMapper.java

~~~java
public interface MenuMapper extends BaseMapper<Menu> {
    public List<Menu> getMenuListByUserId(@Param("userId") Integer userId,
                                          @Param("pid") Integer pid);
}
~~~

先在IMenuService中定义一下：

```java
public interface IMenuService extends IService<Menu>{
  List<Menu> getAllMenu();
  List<Menu> getMenuListByUserId(Integer userId);
}
```

然后在MenuServiceImpl.java中实现

~~~java
@Override
    public List<Menu> getMenuListByUserId(Integer userId) {
        // 一级菜单
        List<Menu> menuList = this.getBaseMapper().getMenuListByUserId(userId, 0);
        // 子菜单
        setMenuChildrenByUserId(userId, menuList);
        return menuList;
    }

    private void setMenuChildrenByUserId(Integer userId, List<Menu> menuList) {
        if (menuList != null) {
            for (Menu menu : menuList) {
                List<Menu> subMenuList = this.getBaseMapper().getMenuListByUserId(userId, menu.getMenuId());
                menu.setChildren(subMenuList);
                // 递归
                setMenuChildrenByUserId(userId,subMenuList);
            }
        }
    }
~~~

通过user/info接口返回数据，修改UserServiceImpl.java中的getUserInfo函数，在橘色下面加入权限列表的查询

UserServiceImpl.java

先增加UserService

```java
@Autowired
private IMenuService menuService;
```

然后在

```java
@Override
public Map<String, Object> getUserInfo(String token)
```

这个函数中添加代码

![image-20230228084606166](md-images/image-20230228084606166.png)

写完之后测试一下接口

### 2. 前端动态路由处理

#### ⑴ 修改原路由配置

**src\router\index.js**，保留基础路由，其它的删掉或注释

~~~js
export const constantRoutes = [
  {
    path: '/login',
    component: () => import('@/views/login/index'),
    hidden: true
  },
  {
    path: '/404',
    component: () => import('@/views/404'),
    hidden: true
  },
  {
    path: '/',
    component: Layout,
    redirect: '/dashboard',
    children: [{
      path: 'dashboard',
      name: 'Dashboard',
      component: () => import('@/views/dashboard/index'),
      meta: { title: '首页', icon: 'dashboard', affix:true ,noCache: false}
    }]
  },  
]
~~~

**需要删除的代码内容如下：**

```javascript
{
  path: '/sys',
  // /sys为一级菜单
  component: Layout,
  redirect: '/sys/user',
  name: 'sysManage',
  meta: { title: '系统管理', icon: 'eye' },
  children: [
    {
      path: 'user',
      name: 'user',
      component: () => import('@/views/sys/user'),
      meta: { title: '用户管理', icon: 'userManager' }
    },
    {
      path: 'role',
      name: 'role',
      component: () => import('@/views/sys/role'),
      meta: { title: '角色管理', icon: '角色管理' }
    }
  ]
},
  //目前这里是写死的，还可以放到数据库中，通过查询显示出来，变成动态的路由

{
  path: '/test',
  component: Layout,
  redirect: '/test/test1',
  name: 'test',
  meta: { title: '测试模块',icon: 'form'},
  children:[
    {
      path: 'test1',
      name: 'test1',
      component: () => import('@/views/test/test1'),
      meta: { title: '功能点一',icon: 'form'}
    },
    {
      path: 'test2',
      name: 'test2',
      component: () => import('@/views/test/test2'),
      meta: { title: '功能点二',icon: 'form'}
    },
    {
      path: 'test3',
      name: 'test3',
      component: () => import('@/views/test/test3'),
      meta: { title: '功能点三',icon: 'form'}
    }
  ]
},

// 404 page must be placed at the end !!!
{ path: '*', redirect: '/404', hidden: true }
```

#### ⑵ 获取菜单数据并保存至Vuex

src\store\modules\user.js

menuList为当前用户的权限菜单

![image-20230228095026359](md-images/image-20230228095026359.png)

定义了变量之后需要定义跟变量menuList一样的方法，在const mutations = {...}中定义(还是在src\store\modules\user.js中修改)

![image-20230228112453656](md-images/image-20230228112453656.png)

还是在src\store\modules\user.js中修改getInfo函数

![image-20230228112654522](md-images/image-20230228112654522.png)

将用户名和头像地址放到vuex之中，const { name, avatar, menuList} = data相当于

```vue
menuList = data.menuList
```

```javascript
commit('SET_MENU_LIST', menuList)
```

把后台传过来的menuList放到SET_MENU_LIST的变量之中

src\store\getters.js

![image-20230228095656102](md-images/image-20230228095656102.png)



#### ⑶ 路由转换：最重要的部分

修改src目录下的permission.js

首先引入一个layout组件

![image-20230228114832777](md-images/image-20230228114832777.png)

调整的位置在permission.js中如图所示

![添加代码的位置](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231010174344270.png)

添加如下的代码

```javascript
// 在上面注释的 在这里添加添加对应代码
// 路由转换
let myRoutes = myFilterAsyncRoutes(store.getters.menuList);
// 404
myRoutes.push({
    path: '*',
    redirect: '/404',
    hidden: true
});
// 动态添加路由
router.addRoutes(myRoutes);
// 存至全局变量
global.myRoutes = myRoutes;

next({...to,replace:true})  // 防止刷新后页面空白
```

**注意上面的代码添加完成之后需要把next()给注释掉**

添加完成之后需要在最后面定义一个方法

![image-20230228163806760](C:\Users\dacai\AppData\Roaming\Typora\typora-user-images\image-20230228163806760.png)

![image-20230228114933271](md-images/image-20230228114933271.png)

原因：重点针对

![路由组件和内容](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231010174934019.png)

这两部分内容进行转换

~~~js
import Layout from '@/layout'
~~~

~~~js
// 在上面注释的 在这里添加添加对应代码
// 路由转换
let myRoutes = myFilterAsyncRoutes(store.getters.menuList);
// 404，
myRoutes.push({
    path: '*',
    redirect: '/404',
    hidden: true
});
// 动态添加路由
router.addRoutes(myRoutes);
// 存至全局变量
global.myRoutes = myRoutes;

next({...to,replace:true})  // 防止刷新后页面空白
~~~

~~~js
function myFilterAsyncRoutes(menuList) {
  menuList.filter(menu => {
    if (menu.component === 'Layout') {
      //如果数据库是Layout字段
      menu.component = Layout
      //将菜单重新转为Layout对象
      console.log(menu.component);
    } else {
      //如果不是Layout字段，证明是一段路径
      //将后台的路径跟views一起进行拼接
      menu.component = require(`@/views/${menu.component}.vue`).default
      //核心：将component进行处理，因为其他字段都不会有问题
      //只有menu.component会存在问题
    }
    // 递归处理子菜单，因为菜单一二三级是不确定的，所以调用递归
    if (menu.children && menu.children.length) {
      menu.children = myFilterAsyncRoutes(menu.children)
    }
    return true
  })
  return menuList;
}
~~~

![数据库中的component字段](/Users/brandon.gu/Library/Application Support/typora-user-images/image-20231010175040342.png)

#### ⑷ 路由合并

src\layout\components\Sidebar\index.vue

![image-20230228115108919](md-images/image-20230228115108919.png)

之前返回的是路由中写死的数据

```javascript
routes(){
  return this.$router.options.routes;
}
```

测试预期结果，不同角色的用户登录后展示的菜单列表不一样。



至此，虽然实现动态菜单功能，但并没有解决安全问题，大家可以思考存在什么问题?













