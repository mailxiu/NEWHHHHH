/*     */ package com.bss.controller;
/*     */ 
/*     */ import com.alibaba.fastjson.JSON;
/*     */ import com.alibaba.fastjson.JSONObject;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.baomidou.mybatisplus.core.metadata.IPage;
/*     */ import com.baomidou.mybatisplus.extension.api.ApiController;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
/*     */ import com.bss.entity.Settlement;
/*     */ import com.bss.service.impl.SettlementServiceImpl;
/*     */ import java.io.Serializable;
/*     */ import java.util.List;
/*     */ import java.util.Map;
/*     */ import javax.annotation.Resource;
/*     */ import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.web.bind.annotation.DeleteMapping;
/*     */ import org.springframework.web.bind.annotation.GetMapping;
/*     */ import org.springframework.web.bind.annotation.PathVariable;
/*     */ import org.springframework.web.bind.annotation.PostMapping;
/*     */ import org.springframework.web.bind.annotation.PutMapping;
/*     */ import org.springframework.web.bind.annotation.RequestBody;
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
/*     */ @RestController
/*     */ @RequestMapping({"settlement"})
/*     */ public class SettlementController
/*     */   extends ApiController
/*     */ {
/*     */   @Resource
/*     */   private SettlementServiceImpl settlementService;
/*     */   
/*     */   @GetMapping
/*     */   public R selectAll(Page<Settlement> page, Settlement settlement) {
/*  48 */     return success(this.settlementService.page((IPage)page, (Wrapper)new QueryWrapper(settlement)));
/*     */   }
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping({"/sum"})
/*     */   public R getSum(String uid) {
/*  55 */     QueryWrapper queryWrapper = new QueryWrapper();
/*     */     
/*  57 */     queryWrapper.select(new String[] { "IFNULL(count(*),0) as total,IFNULL(sum(total),0) as points" });
/*     */     
/*  59 */     queryWrapper.eq("uid", uid);
/*     */     
/*  61 */     Map<String, Object> map = this.settlementService.getMap((Wrapper)queryWrapper);
/*     */     
/*  63 */     JSONObject data = (JSONObject)JSON.toJSON(map);
/*     */     
/*  65 */     return success(data);
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
/*     */   @PostMapping({"/list"})
/*     */   public R getList(@RequestParam(name = "merchant") String merchant, @RequestParam(name = "uid", defaultValue = "") Integer uid, @RequestParam(name = "month", defaultValue = "") String month, @RequestParam(name = "pageIndex") Integer pageIndex) {
/*  79 */     QueryWrapper<Settlement> queryWrapper = new QueryWrapper();
/*     */     
/*  81 */     queryWrapper.eq("uid", uid);
/*     */     
/*  83 */     if (!month.equals("")) {
/*  84 */       queryWrapper.apply(true, "date_format(create_time, \"%Y-%m\")=\"" + month + "\"", new Object[0]);
/*     */     }
/*     */     
/*  87 */     queryWrapper.orderByDesc("create_time");
/*     */     
/*  89 */     IPage<Settlement> iPage = this.settlementService.page((IPage)new Page(pageIndex.intValue(), 12L), (Wrapper)queryWrapper);
/*     */     
/*  91 */     return success(iPage.getRecords());
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
/*     */ 
/*     */   
/*     */   @PostMapping({"/list_type"})
/*     */   public R list_type(@RequestParam(name = "merchant") String merchant, @RequestParam(name = "uid", defaultValue = "") Integer uid, @RequestParam(name = "type", defaultValue = "卖货提成") String type, @RequestParam(name = "pageIndex") Integer pageIndex) {
/* 107 */     JSONObject data = new JSONObject();
/*     */     
/* 109 */     QueryWrapper<Settlement> queryWrapper = new QueryWrapper();
/*     */     
/* 111 */     queryWrapper.eq("merchant", merchant);
/* 112 */     queryWrapper.eq("uid", uid);
/*     */     
/* 114 */     IPage<Settlement> iPage = this.settlementService.page((IPage)new Page(pageIndex.intValue(), 12L), (Wrapper)queryWrapper);
/*     */     
/* 116 */     data.put("count", Integer.valueOf(iPage.getRecords().size()));
/* 117 */     data.put("list", iPage.getRecords());
/*     */     
/* 119 */     return success(iPage.getRecords());
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping({"{id}"})
/*     */   public R selectOne(@PathVariable Serializable id) {
/* 130 */     return success(this.settlementService.getById(id));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping
/*     */   public R insert(@RequestBody Settlement settlement) {
/* 141 */     return success(Boolean.valueOf(this.settlementService.save(settlement)));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @PutMapping
/*     */   public R update(@RequestBody Settlement settlement) {
/* 152 */     return success(Boolean.valueOf(this.settlementService.updateById(settlement)));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @DeleteMapping
/*     */   public R delete(@RequestParam("idList") List<Long> idList) {
/* 163 */     return success(Boolean.valueOf(this.settlementService.removeByIds(idList)));
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\SettlementController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */