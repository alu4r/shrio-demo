package cn.itcast.shiro;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.ArrayList;
import java.util.List;

/**
 * @author liulu
 * @date 2019/11/14 21:38
 * @desc 自定义realm对象
 */
public class PermissionRealm extends AuthorizingRealm {

    @Override
    public void setName(String name) {
        super.setName("permissionRealm");
    }
    /**
     * 代表授权 根据认证的数据获取到权限信息
     *
     * @param principalCollection 包含了所有的安全数据
     * @return 授权数据
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println("执行授权方法");
        //1.获取到安全数据
        String userName = (String) principalCollection.getPrimaryPrincipal();
        //2.根据id查询用户
        //3.查询用户的角色和权限信息
        List<String> perms = new ArrayList<>();
        perms.add("user:save");
        perms.add("user:update");

        List<String> roles = new ArrayList<>();
        roles.add("role1");
        roles.add("role2");
        //4.构造返回
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        //设置权限的集合
        info.addStringPermissions(perms);
        //设置角色集合
        info.addRoles(roles);
        return info;
    }

    /**
     * 代表认证  比较用户名和密码是否和数据库中的一致
     * 将安全数据存入到shiro中进行保管
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        System.out.println("执行认证方法");
        //1.构造token
        UsernamePasswordToken upToken = (UsernamePasswordToken) authenticationToken;
        //获取用户名和密码
        String username = upToken.getUsername();
        String password = new String(upToken.getPassword());
        //3.根据用户名查询数据库密码
        if ("123456".equals(password)) {
            //登陆成功，想shiro中存放安全数据
            SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(username,password,getName());
            return info;
        }else {
            throw new RuntimeException("用户名或者密码错误");
        }
    }
}
