/*    */ package com.bss.controller;
/*    */ 
/*    */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*    */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*    */ import com.baomidou.mybatisplus.extension.api.ApiController;
/*    */ import com.baomidou.mybatisplus.extension.api.R;
/*    */ import com.bss.entity.Dividend;
/*    */ import com.bss.entity.DividendVO;
/*    */ import com.bss.service.DividendService;
/*    */ import javax.annotation.Resource;
/*    */ import javax.servlet.http.HttpSession;
/*    */ import org.apache.shiro.authz.annotation.RequiresPermissions;
/*    */ import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.web.bind.annotation.DeleteMapping;
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
/*    */ @RestController
/*    */ @RequestMapping({"dividend"})
/*    */ public class DividendController
/*    */   extends ApiController
/*    */ {
/*    */   @Resource
/*    */   private DividendService dividendService;
/*    */   
/*    */   @RequiresRoles("Admin")
/*    */   @PostMapping({"/update"})
/*    */   public R update(DividendVO dividendVO, HttpSession session) {
/* 42 */     Dividend dividend = new Dividend();
/*    */     
/* 44 */     if (dividendVO.getId().intValue() == 0) {
/*    */ 
/*    */       
/* 47 */       Dividend oldDividend = (Dividend)this.dividendService.getOne((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("relation", dividendVO.getRelation())).eq("request_grade", dividendVO.getRequestGrade())).eq("response_grade", dividendVO.getResponseGrade()));
/*    */       
/* 49 */       if (oldDividend != null) {
/* 50 */         return success(Boolean.valueOf(false)).setMsg("新增失败,推广分佣配置已存在").setCode(102L);
/*    */       }
/*    */       
/* 53 */       dividend.setId(Integer.valueOf(0));
/*    */     } else {
/*    */       
/* 56 */       dividend = (Dividend)this.dividendService.getOne((Wrapper)(new QueryWrapper()).eq("id", dividendVO.getId()));
/*    */     } 
/*    */     
/* 59 */     if (dividend == null) {
/* 60 */       return success(Boolean.valueOf(false)).setMsg("修改失败,推广分佣配置不存在").setCode(101L);
/*    */     }
/*    */ 
/*    */ 
/*    */     
/* 65 */     dividend.setRelation(dividendVO.getRelation());
/* 66 */     dividend.setRequestGrade(dividendVO.getRequestGrade());
/* 67 */     dividend.setResponseGrade(dividendVO.getResponseGrade());
/* 68 */     dividend.setSpread(dividendVO.getSpread());
/*    */     
/* 70 */     boolean update = this.dividendService.saveOrUpdate(dividend);
/*    */     
/* 72 */     return success(Boolean.valueOf(update)).setMsg("修改成功");
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   @RequiresRoles("Admin")
/*    */   @DeleteMapping({"del"})
/*    */   public R delete(@RequestParam("id") Integer id) {
/* 84 */     return success(Boolean.valueOf(this.dividendService.removeById(id)));
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\DividendController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */