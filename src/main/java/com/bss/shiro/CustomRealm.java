/*     */ package com.bss.shiro;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.bss.entity.*;
/*     */
/*     */
/*     */
/*     */ import com.bss.service.PermissionService;
import com.bss.service.UserService;
/*     */ import com.bss.service.impl.RolePermissionServiceImpl;
/*     */ import com.bss.service.impl.RoleServiceImpl;
/*     */ import com.bss.service.impl.UserRoleServiceImpl;
/*     */ import java.util.ArrayList;
/*     */ import java.util.List;
/*     */ import javax.annotation.Resource;
/*     */ import org.apache.shiro.authc.*;
/*     */
/*     */
/*     */
/*     */ import org.apache.shiro.authz.AuthorizationInfo;
/*     */ import org.apache.shiro.authz.SimpleAuthorizationInfo;
/*     */ import org.apache.shiro.realm.AuthorizingRealm;
/*     */ import org.apache.shiro.subject.PrincipalCollection;
/*     */ import org.apache.shiro.util.ByteSource;
/*     */ import org.slf4j.Logger;
/*     */ import org.slf4j.LoggerFactory;
/*     */ 
/*     */ public class CustomRealm extends AuthorizingRealm {
/*  28 */   private static final Logger log = LoggerFactory.getLogger(com.bss.shiro.CustomRealm.class);
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private UserService userService;
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private RoleServiceImpl roleService;
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private PermissionService permissionService;
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private UserRoleServiceImpl userRoleService;
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private RolePermissionServiceImpl rolePermissionService;
/*     */ 
/*     */ 
/*     */   
/*     */   protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
/*  56 */     SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
/*     */     
/*  58 */     User user = (User)principalCollection.getPrimaryPrincipal();
/*     */ 
/*     */     
/*  61 */     List<UserRole> userRoles = this.userRoleService.list((Wrapper)(new QueryWrapper()).eq("user_id", user.getId()));
/*     */ 
/*     */     
/*  64 */     List<Role> roles = new ArrayList<>();
/*     */     
/*  66 */     for (int i = 0; i < userRoles.size(); i++) {
/*  67 */       Role role = (Role)this.roleService.getOne((Wrapper)(new QueryWrapper()).eq("id", ((UserRole)userRoles.get(i)).getRoleId()));
/*  68 */       roles.add(role);
/*     */     } 
/*     */     
/*  71 */     List<RolePermission> rolePermissionList = new ArrayList<>();
/*  72 */     List<String> permissions = new ArrayList<>();
/*     */     
/*  74 */     for (Role role : roles) {
/*  75 */       info.addRole(role.getSn());
/*  76 */       rolePermissionList.addAll(this.rolePermissionService.list((Wrapper)(new QueryWrapper()).eq("role_id", role.getId())));
/*     */     } 
/*     */     
/*  79 */     for (RolePermission rp : rolePermissionList) {
/*  80 */       permissions.add(((Permission)this.permissionService.getOne((Wrapper)(new QueryWrapper()).eq("id", rp.getPermissionId()))).getName());
/*     */     }
/*     */     
/*  83 */     info.addStringPermissions(permissions);
/*     */ 
/*     */     
/*  86 */     return (AuthorizationInfo)info;
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
/*  97 */     String userName = (String)authenticationToken.getPrincipal();
/*     */ 
/*     */     
/* 100 */     QueryWrapper<User> queryWrapper = new QueryWrapper();
/* 101 */     queryWrapper.eq("username", userName);
/* 102 */     User user = (User)this.userService.getOne((Wrapper)queryWrapper);
/*     */ 
/*     */     
/* 105 */     if (userName == null || user == null) {
/* 106 */       return null;
/*     */     }
/*     */ 
/*     */     
/* 110 */     if (user.getState().intValue() == 0) {
/* 111 */       throw new LockedAccountException("账户已被锁定");
/*     */     }
/*     */     
/* 114 */     SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(user, user.getPassword(), ByteSource.Util.bytes(user.getUsername()), getName());
/*     */     
/* 116 */     return (AuthenticationInfo)authenticationInfo;
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\shiro\CustomRealm.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */