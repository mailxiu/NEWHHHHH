/*    */ package com.bss.task;
/*    */ 
/*    */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*    */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*    */ import com.bss.entity.Member;
/*    */ import com.bss.service.impl.MemberServiceImpl;
/*    */ import java.util.Date;
/*    */ import java.util.List;
/*    */ import javax.annotation.Resource;
/*    */ import org.slf4j.Logger;
/*    */ import org.slf4j.LoggerFactory;
/*    */ import org.springframework.scheduling.annotation.Scheduled;
/*    */ import org.springframework.stereotype.Component;
/*    */ 
/*    */ 
/*    */ 
/*    */ @Component
/*    */ public class ExpireTask
/*    */ {
/* 20 */   private static final Logger log = LoggerFactory.getLogger(com.bss.task.ExpireTask.class);
/*    */ 
/*    */ 
/*    */   
/*    */   @Resource
/*    */   private MemberServiceImpl memberService;
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   @Scheduled(cron = "0 0 * * * ?")
/*    */   public void monitorGrade() {
/* 32 */     log.info("===执行会员过期监测任务===");
/*    */ 
/*    */     
/* 35 */     List<Member> list = this.memberService.list((Wrapper)(new QueryWrapper()).ne("partner", Integer.valueOf(1)));
/*    */     
/* 37 */     list.forEach(member -> {
/*    */           Date expireTime = member.getExpireTime();
/*    */ 
/*    */           
/*    */           if (member != null && member.getExpireTime() != null && !expireTime.after(new Date())) {
/*    */             log.info("UID:{},会员到期：{}", member.getUid(), member.getExpireTime());
/*    */ 
/*    */             
/*    */             member.setExpireTime(null);
/*    */ 
/*    */             
/*    */             member.setPartner(Integer.valueOf(1));
/*    */             
/*    */             this.memberService.saveOrUpdate(member);
/*    */           } 
/*    */         });
/*    */     
/* 54 */     log.info("===会员过期监测任务结束===");
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\task\ExpireTask.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */