/*     */ package com.bss.controller;
/*     */ 
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.baomidou.mybatisplus.core.metadata.IPage;
/*     */ import com.baomidou.mybatisplus.extension.api.ApiController;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
/*     */ import com.bss.entity.Screen;
/*     */ import com.bss.entity.ScreenVo;
/*     */ import com.bss.entity.User;
/*     */ import com.bss.service.ScreenService;
/*     */ import java.io.Serializable;
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
/*     */ 
/*     */ 
/*     */ @RestController
/*     */ @RequestMapping({"screen"})
/*     */ public class ScreenController
/*     */   extends ApiController
/*     */ {
/*     */   @Resource
/*     */   private ScreenService screenService;
/*     */   
/*     */   @GetMapping
/*     */   public R selectAll(Page<Screen> page, Screen screen) {
/*  45 */     return success(this.screenService.page((IPage)page, (Wrapper)new QueryWrapper(screen)));
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
/*  56 */     return success(this.screenService.getById(id));
/*     */   }
/*     */ 
/*     */   
/*     */   @PostMapping({"/add"})
/*     */   public R insert(ScreenVo screenVo, HttpSession session) {
/*  62 */     User user = (User)session.getAttribute("user");
/*     */     
/*  64 */     Screen screen = (Screen)this.screenService.getOne((Wrapper)new QueryWrapper());
/*     */     
/*  66 */     if (screen == null) {
/*  67 */       screen = new Screen();
/*  68 */       screen.setId(Integer.valueOf(0));
/*     */     } 
/*     */     
/*  71 */     screen.setMerchant(user.getMerchant());
/*  72 */     screen.setWidth(screenVo.getWidth());
/*  73 */     screen.setHeight(screenVo.getHeight());
/*  74 */     screen.setRadius(screenVo.getRadius());
/*  75 */     screen.setBgColor(screenVo.getBgColor());
/*  76 */     screen.setMd(screenVo.getMd());
/*  77 */     screen.setIconUrl(screenVo.getIconUrl());
/*  78 */     screen.setIconPositionY(screenVo.getIconPositionY());
/*  79 */     screen.setIconPositionX(screenVo.getIconPositionX());
/*  80 */     screen.setIconOffset(screenVo.getIconOffset());
/*     */     
/*  82 */     boolean save = this.screenService.saveOrUpdate(screen);
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
/*     */   public R update(@RequestBody Screen screen) {
/*  95 */     return success(Boolean.valueOf(this.screenService.updateById(screen)));
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
/* 106 */     return success(Boolean.valueOf(this.screenService.removeByIds(idList)));
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\ScreenController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */