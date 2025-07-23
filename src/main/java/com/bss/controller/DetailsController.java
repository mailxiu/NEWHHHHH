/*    */ package com.bss.controller;
/*    */ 
/*    */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*    */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*    */ import com.baomidou.mybatisplus.extension.api.ApiController;
/*    */ import com.baomidou.mybatisplus.extension.api.R;
/*    */ import com.bss.entity.Details;
/*    */ import com.bss.entity.DetailsVo;
/*    */ import com.bss.entity.User;
/*    */ import com.bss.service.DetailsService;
/*    */ import javax.annotation.Resource;
/*    */ import javax.servlet.http.HttpSession;
/*    */ import org.springframework.web.bind.annotation.PostMapping;
/*    */ import org.springframework.web.bind.annotation.RequestMapping;
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
/*    */ @RestController
/*    */ @RequestMapping({"details"})
/*    */ public class DetailsController
/*    */   extends ApiController
/*    */ {
/*    */   @Resource
/*    */   private DetailsService detailsService;
/*    */   
/*    */   @PostMapping({"/add"})
/*    */   public R insert(DetailsVo detailsVo, HttpSession session) {
/* 43 */     User user = (User)session.getAttribute("user");
/*    */     
/* 45 */     Details details = (Details)this.detailsService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("pid", detailsVo.getPid()));
/*    */     
/* 47 */     if (details == null) {
/* 48 */       details = new Details();
/* 49 */       details.setMerchant(user.getMerchant());
/*    */     } 
/*    */     
/* 52 */     details.setPid(detailsVo.getPid());
/* 53 */     details.setMd(detailsVo.getMd());
/* 54 */     details.setLook(Integer.valueOf(1000));
/*    */ 
/*    */     
/* 57 */     boolean save = this.detailsService.saveOrUpdate(details);
/*    */     
/* 59 */     return success(Boolean.valueOf(save));
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\DetailsController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */