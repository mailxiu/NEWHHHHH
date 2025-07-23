/*     */ package com.bss.controller;
/*     */ 
/*     */ import com.baomidou.mybatisplus.extension.api.ApiController;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.bss.entity.User;
/*     */ import com.bss.entity.UserRole;
/*     */ import com.bss.entity.UserVo;
/*     */ import com.bss.service.UserService;
/*     */ import com.bss.service.impl.UserRoleServiceImpl;
/*     */ import java.text.DateFormat;
/*     */ import java.text.SimpleDateFormat;
/*     */ import java.util.Calendar;
/*     */ import javax.annotation.Resource;
/*     */ import javax.servlet.http.HttpSession;
/*     */ import org.apache.shiro.crypto.hash.Md5Hash;
/*     */ import org.springframework.web.bind.annotation.DeleteMapping;
/*     */ import org.springframework.web.bind.annotation.ModelAttribute;
/*     */ import org.springframework.web.bind.annotation.PostMapping;
/*     */ import org.springframework.web.bind.annotation.RequestMapping;
/*     */ import org.springframework.web.bind.annotation.RequestParam;
/*     */ import org.springframework.web.bind.annotation.RestController;
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ @RestController
/*     */ @RequestMapping({"user"})
/*     */ public class UserController
/*     */   extends ApiController
/*     */ {
/*     */   @Resource
/*     */   private UserService userService;
/*     */   @Resource
/*     */   private UserRoleServiceImpl userRoleService;
/*     */   
/*     */   @PostMapping({"/add"})
/*     */   public R add(@ModelAttribute UserVo userVo) {
/*  48 */     Calendar cal = Calendar.getInstance();
/*  49 */     DateFormat createTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
/*     */     
/*  51 */     Md5Hash md5Hash = new Md5Hash(userVo.getPassword(), userVo.getUsername(), 3);
/*     */     
/*  53 */     User user = new User();
/*  54 */     user.setId(Integer.valueOf(0));
/*  55 */     user.setUsername(userVo.getUsername());
/*  56 */     user.setPassword(md5Hash.toString());
/*  57 */     user.setName(userVo.getName());
/*  58 */     user.setPattern("operate");
/*  59 */     user.setDesign("operate");
/*  60 */     user.setAppid(userVo.getAppid());
/*  61 */     user.setState(Integer.valueOf(1));
/*  62 */     user.setCreateTime(createTime.format(cal.getTime()));
/*     */     
/*  64 */     this.userService.save(user);
/*     */     
/*  66 */     String merchant = String.valueOf(Integer.valueOf(user.getId().toString()).intValue() + 100000);
/*     */     
/*  68 */     user.setMerchant(merchant);
/*     */     
/*  70 */     UserRole userRole = new UserRole();
/*  71 */     userRole.setUserId(user.getId());
/*  72 */     userRole.setRoleId(Integer.valueOf(2));
/*     */     
/*  74 */     this.userRoleService.save(userRole);
/*     */     
/*  76 */     return success(Boolean.valueOf(this.userService.saveOrUpdate(user)));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/update_freeze"})
/*     */   public R update_freeze(Integer id, Integer state) {
/*  87 */     User user = (User)this.userService.getById(id);
/*     */     
/*  89 */     if (user != null) {
/*  90 */       user.setState(state);
/*  91 */       this.userService.saveOrUpdate(user);
/*     */     } 
/*     */     
/*  94 */     return success(user);
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/edit_pwd"})
/*     */   public R edit_pwd(String oldpwd, String newpwd, String confirmpwd, HttpSession session) {
/* 108 */     User user = (User)session.getAttribute("user");
/*     */     
/* 110 */     if (!newpwd.equals(confirmpwd)) {
/* 111 */       return success(null).setMsg("修改失败，两次密码输入不一致").setCode(102L);
/*     */     }
/*     */     
/* 114 */     Md5Hash md5Hash = new Md5Hash(oldpwd, user.getUsername(), 3);
/*     */     
/* 116 */     if (!md5Hash.toString().equals(user.getPassword())) {
/* 117 */       return success(null).setMsg("修改失败，旧密码输入错误").setCode(101L);
/*     */     }
/*     */     
/* 120 */     Md5Hash n_md5Hash = new Md5Hash(newpwd, user.getUsername(), 3);
/*     */     
/* 122 */     user.setPassword(n_md5Hash.toString());
/*     */     
/* 124 */     boolean update = this.userService.saveOrUpdate(user);
/*     */     
/* 126 */     if (!update) {
/* 127 */       return success(null).setMsg("修改失败，未知原因").setCode(102L);
/*     */     }
/*     */     
/* 130 */     return success(Boolean.valueOf(this.userService.updateById(user)));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @DeleteMapping({"/del"})
/*     */   public R delete(@RequestParam("id") Integer id) {
/* 140 */     return success(Boolean.valueOf(this.userService.removeById(id)));
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\UserController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */