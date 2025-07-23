/*    */ package com.bss.service.impl;
/*    */ 
/*    */ import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
/*    */ import com.bss.entity.Project;
/*    */ import com.bss.mapper.ProjectMapper;
/*    */ import com.bss.service.ProjectService;
/*    */ import java.util.List;
/*    */ import javax.annotation.Resource;
/*    */ import org.springframework.stereotype.Service;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ @Service
/*    */ public class ProjectServiceImpl
/*    */   extends ServiceImpl<ProjectMapper, Project>
/*    */   implements ProjectService
/*    */ {
/*    */   @Resource
/*    */   private ProjectMapper projectMapper;
/*    */   
/*    */   public List<String> stateList(String merchant) {
/* 25 */     return this.projectMapper.stateList(merchant);
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\service\impl\ProjectServiceImpl.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */