/*    */ package com.bss.controller;
/*    */ 
/*    */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*    */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*    */ import com.baomidou.mybatisplus.extension.api.ApiController;
/*    */ import com.baomidou.mybatisplus.extension.api.R;
/*    */ import com.bss.entity.Message;
/*    */ import com.bss.service.MessageService;
/*    */ import javax.annotation.Resource;
/*    */ import org.springframework.web.bind.annotation.DeleteMapping;
/*    */ import org.springframework.web.bind.annotation.RequestMapping;
/*    */ import org.springframework.web.bind.annotation.RequestParam;
/*    */ import org.springframework.web.bind.annotation.RestController;
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
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ @RestController
/*    */ @RequestMapping({"message"})
/*    */ public class MessageController
/*    */   extends ApiController
/*    */ {
/*    */   @Resource
/*    */   private MessageService messageService;
/*    */   
/*    */   @RequestMapping({"/add"})
/*    */   public R add(String uid, String title, String info) {
/* 43 */     Message message = new Message();
/* 44 */     message.setId(Integer.valueOf(0));
/* 45 */     message.setUid(uid);
/* 46 */     message.setTitle(title);
/* 47 */     message.setInfo(info);
/* 48 */     message.setState(Integer.valueOf(0));
/*    */     
/* 50 */     boolean save = this.messageService.save(message);
/*    */ 
/*    */     
/* 53 */     return success(Boolean.valueOf(save));
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   @DeleteMapping({"deleteRead"})
/*    */   public R deleteRead() {
/* 62 */     return success(Boolean.valueOf(this.messageService.remove((Wrapper)(new QueryWrapper()).eq("state", Integer.valueOf(1)))));
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   @DeleteMapping({"del"})
/*    */   public R delete(@RequestParam("id") Integer id) {
/* 72 */     return success(Boolean.valueOf(this.messageService.removeById(id)));
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\MessageController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */