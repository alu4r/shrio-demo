package cn.itcast.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Before;
import org.junit.Test;

public class ShiroTest02 {

    private SecurityManager securityManager;
    @Before
    public void init(){
        //1.根据配置文件创建SecurityManagerFactory
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-test-2.ini");
        //2.通过工厂获取SecurityManager
        this.securityManager = factory.getInstance();
        //3.将SecurityManager绑定到当前运行环境
        SecurityUtils.setSecurityManager(this.securityManager);
    }

    @Test
    public void testLogin() {
        //4.从当前运行环境中构造subject
        Subject subject = SecurityUtils.getSubject();
        //5.构造shiro登录的数据
        String username = "zhangsan";
        String password = "123456";
        UsernamePasswordToken token = new UsernamePasswordToken(username,password);
        //6.主体登陆
        subject.login(token);
        //登陆成功后完成授权，检验当前用户是否具有操作权限，是否具有某个角色
        System.out.println("是否具有操作权限save==>"+subject.isPermitted("user:save"));
        System.out.println("是否具有role1角色==>"+subject.hasRole("role1"));


    }

}
