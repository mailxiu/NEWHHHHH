/*    */ package com.bss.controller;
/*    */ 
/*    */ import com.baomidou.mybatisplus.extension.api.ApiController;
/*    */ import com.baomidou.mybatisplus.extension.api.R;
/*    */ import com.bss.entity.ComplaintRefer;
/*    */ import com.bss.entity.ComplaintReferVo;
/*    */ import com.bss.service.ComplaintReferService;
/*    */ import javax.annotation.Resource;
/*    */ import org.springframework.web.bind.annotation.DeleteMapping;
/*    */ import org.springframework.web.bind.annotation.PostMapping;
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
/*    */ @RestController
/*    */ @RequestMapping({"complaintRefer"})
/*    */ public class ComplaintReferController
/*    */   extends ApiController
/*    */ {
/*    */   @Resource
/*    */   private ComplaintReferService complaintReferService;
/*    */   
/*    */   @PostMapping({"add"})
/*    */   public R delete(ComplaintReferVo complaintReferVo) {
/* 42 */     ComplaintRefer complaintRefer = new ComplaintRefer();
/* 43 */     complaintRefer.setId(Integer.valueOf(0));
/* 44 */     complaintRefer.setName(complaintReferVo.getName());
/* 45 */     complaintRefer.setSort(complaintReferVo.getSort());
/* 46 */     complaintRefer.setState(complaintReferVo.getState());
/*    */     
/* 48 */     return success(Boolean.valueOf(this.complaintReferService.save(complaintRefer)));
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   @DeleteMapping
/*    */   public R delete(@RequestParam("id") Integer idList) {
/* 59 */     return success(Boolean.valueOf(this.complaintReferService.removeById(idList)));
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\ComplaintReferController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */