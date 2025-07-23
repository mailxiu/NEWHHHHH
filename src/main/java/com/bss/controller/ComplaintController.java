/*     */ package com.bss.controller;
/*     */ 
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.baomidou.mybatisplus.extension.api.ApiController;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.bss.entity.Complaint;
/*     */ import com.bss.entity.ComplaintItem;
/*     */ import com.bss.service.ComplaintService;
/*     */ import com.bss.service.impl.ComplaintItemServiceImpl;
/*     */ import java.util.List;
/*     */ import javax.annotation.Resource;
/*     */ import org.springframework.web.bind.annotation.DeleteMapping;
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
/*     */ 
/*     */ 
/*     */ 
/*     */ @RestController
/*     */ @RequestMapping({"complaint"})
/*     */ public class ComplaintController
/*     */   extends ApiController
/*     */ {
/*     */   @Resource
/*     */   private ComplaintService complaintService;
/*     */   @Resource
/*     */   private ComplaintItemServiceImpl complaintItemService;
/*     */   
/*     */   @PostMapping({"replyComplaint"})
/*     */   public R replyComplaint(@RequestParam("id") Integer id, String content) {
/*  47 */     Complaint complaint = (Complaint)this.complaintService.getById(id);
/*     */ 
/*     */     
/*  50 */     if (complaint == null) {
/*  51 */       return R.failed("投诉不存在");
/*     */     }
/*     */     
/*  54 */     ComplaintItem complaintItem = new ComplaintItem();
/*     */     
/*  56 */     complaintItem.setId(Integer.valueOf(0));
/*  57 */     complaintItem.setComplaintNumber(complaint.getComplaintNumber());
/*  58 */     complaintItem.setSessionType("platform");
/*  59 */     complaintItem.setContent(content);
/*  60 */     complaintItem.setImages("");
/*     */     
/*  62 */     boolean save = this.complaintItemService.save(complaintItem);
/*     */ 
/*     */     
/*  65 */     return success(Boolean.valueOf(save));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"closeComplaint"})
/*     */   public R closeComplaint(@RequestParam("id") Integer id) {
/*  77 */     Complaint complaint = (Complaint)this.complaintService.getById(id);
/*     */ 
/*     */     
/*  80 */     if (complaint == null) {
/*  81 */       return R.failed("投诉不存在");
/*     */     }
/*     */     
/*  84 */     complaint.setState(Integer.valueOf(1));
/*     */     
/*  86 */     boolean saveOrUpdate = this.complaintService.saveOrUpdate(complaint);
/*     */     
/*  88 */     return success(Boolean.valueOf(saveOrUpdate));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @DeleteMapping({"deleteComplete"})
/*     */   public R deleteComplete() {
/*  98 */     return success(Boolean.valueOf(this.complaintService.remove((Wrapper)(new QueryWrapper()).eq("state", Integer.valueOf(1)))));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @DeleteMapping
/*     */   public R delete(@RequestParam("id") Integer id) {
/* 110 */     Complaint complaint = (Complaint)this.complaintService.getById(id);
/*     */ 
/*     */     
/* 113 */     if (complaint == null) {
/* 114 */       return R.failed("投诉不存在");
/*     */     }
/*     */ 
/*     */     
/* 118 */     List<ComplaintItem> items = this.complaintItemService.list((Wrapper)(new QueryWrapper()).eq("complaint_number", complaint.getComplaintNumber()));
/*     */ 
/*     */     
/* 121 */     for (ComplaintItem item : items) {
/* 122 */       this.complaintItemService.removeById(item.getId());
/*     */     }
/*     */ 
/*     */     
/* 126 */     return success(Boolean.valueOf(this.complaintService.removeById(id)));
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\ComplaintController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */