/*    */ package com.bss.service.impl;
/*    */ 
/*    */ import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
/*    */ import com.bss.entity.Role;
/*    */ import com.bss.mapper.RoleMapper;
/*    */ import com.bss.service.RoleService;
/*    */ import java.util.ArrayList;
/*    */ import java.util.List;
/*    */ import javax.annotation.Resource;
/*    */ import org.springframework.stereotype.Service;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ @Service
/*    */ public class RoleServiceImpl
/*    */   extends ServiceImpl<RoleMapper, Role>
/*    */   implements RoleService
/*    */ {
/*    */   @Resource
/*    */   private RoleMapper roleMapper;
/*    */   
/*    */   public List<Role> getRoles(Integer user_id) {
/* 32 */     List<Integer> list = this.roleMapper.getList(user_id);
/*    */     
/* 34 */     List<Role> roles = new ArrayList<>();
/*    */     
/* 36 */     list.forEach(u -> {
/*    */           Role role = (Role)this.roleMapper.selectById(u);
/*    */ 
/*    */           
/*    */           if (role != null) {
/*    */             roles.add(role);
/*    */           }
/*    */         });
/*    */     
/* 45 */     return roles;
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\service\impl\RoleServiceImpl.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */