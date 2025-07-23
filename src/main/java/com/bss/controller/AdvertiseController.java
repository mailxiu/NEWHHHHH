/*     */ package com.bss.controller;
/*     */ 
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.baomidou.mybatisplus.core.metadata.IPage;
/*     */ import com.baomidou.mybatisplus.extension.api.ApiController;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
/*     */ import com.bss.entity.Advertise;
/*     */ import com.bss.entity.AdvertiseVo;
/*     */ import com.bss.entity.User;
/*     */ import com.bss.service.AdvertiseService;
/*     */ import java.io.Serializable;
/*     */ import java.text.DateFormat;
/*     */ import java.text.SimpleDateFormat;
/*     */ import java.util.Calendar;
/*     */ import java.util.List;
/*     */ import javax.annotation.Resource;
/*     */ import javax.servlet.http.HttpSession;
/*     */ import org.springframework.web.bind.annotation.DeleteMapping;
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
/*     */ @RestController
/*     */ @RequestMapping({"advertise"})
/*     */ public class AdvertiseController
/*     */   extends ApiController
/*     */ {
/*     */   @Resource
/*     */   private AdvertiseService advertiseService;
/*     */   
/*     */   @GetMapping
/*     */   public R selectAll(Page<Advertise> page, Advertise advertise) {
/*  46 */     return success(this.advertiseService.page((IPage)page, (Wrapper)new QueryWrapper(advertise)));
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
/*  57 */     return success(this.advertiseService.getById(id));
/*     */   }
/*     */ 
/*     */   
/*     */   @PostMapping({"/add"})
/*     */   public R insert(AdvertiseVo advertiseVo, HttpSession session) {
/*  63 */     Calendar cal = Calendar.getInstance();
/*     */     
/*  65 */     DateFormat stateTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
/*     */     
/*  67 */     User user = (User)session.getAttribute("user");
/*     */     
/*  69 */     Advertise advertise = (Advertise)this.advertiseService.getOne((Wrapper)(new QueryWrapper()).eq("merchant", user.getMerchant()));
/*     */     
/*  71 */     if (advertise == null) {
/*  72 */       advertise = new Advertise();
/*  73 */       advertise.setId(Integer.valueOf(0));
/*     */     } 
/*     */     
/*  76 */     advertise.setMerchant(user.getMerchant());
/*  77 */     advertise.setOrient(advertiseVo.getOrient());
/*  78 */     advertise.setMd(advertiseVo.getMd());
/*  79 */     advertise.setState(advertiseVo.getState());
/*  80 */     advertise.setCreateTime(stateTime.format(cal.getTime()));
/*     */     
/*  82 */     boolean save = this.advertiseService.saveOrUpdate(advertise);
/*     */     
/*  84 */     return success(Boolean.valueOf(save));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PutMapping
/*     */   public R update(@RequestBody Advertise advertise) {
/*  95 */     return success(Boolean.valueOf(this.advertiseService.updateById(advertise)));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @DeleteMapping
/*     */   public R delete(@RequestParam("idList") List<Long> idList) {
/* 106 */     return success(Boolean.valueOf(this.advertiseService.removeByIds(idList)));
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\AdvertiseController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */