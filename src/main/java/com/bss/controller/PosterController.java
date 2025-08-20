/*     */ package com.bss.controller;
/*     */ 
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.baomidou.mybatisplus.core.metadata.IPage;
/*     */ import com.baomidou.mybatisplus.extension.api.ApiController;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
/*     */ import com.bss.entity.Poster;
/*     */ import com.bss.entity.User;
/*     */ import com.bss.service.PosterService;
/*     */ import java.io.Serializable;
/*     */ import javax.annotation.Resource;
/*     */ import javax.servlet.http.HttpSession;
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
/*     */ @RestController
/*     */ @RequestMapping({"poster"})
/*     */ public class PosterController
/*     */   extends ApiController
/*     */ {
/*     */   @Resource
/*     */   private PosterService posterService;
/*     */   
/*     */   @GetMapping
/*     */   public R selectAll(Page<Poster> page, Poster poster) {
/*  41 */     return success(this.posterService.page((IPage)page, (Wrapper)new QueryWrapper(poster)));
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
/*  52 */     return success(this.posterService.getById(id));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/add"})
/*     */   public R insert(String main_image, Integer img_w, Integer img_h, Integer qr_w, Integer qr_h, Integer qr_x, Integer qr_y, String qr_color, Boolean is_hyaline, Integer state, HttpSession session) {
/*  63 */     User user = (User)session.getAttribute("user");
/*     */     
/*  65 */     Poster poster = new Poster();
/*  66 */     poster.setId(Integer.valueOf(0));
/*  67 */     poster.setMerchant(Long.valueOf(user.getMerchant()));
/*  68 */     poster.setMainImage(main_image);
/*  69 */     poster.setImgW(img_w);
/*  70 */     poster.setImgH(img_h);
/*  71 */     poster.setQrW(qr_w);
/*  72 */     poster.setQrH(qr_h);
/*  73 */     poster.setQrX(qr_x);
/*  74 */     poster.setQrY(qr_y);
/*  75 */     poster.setQrColor(qr_color);
/*  76 */     poster.setIsHyaline(is_hyaline);
/*  77 */     poster.setState(state);
/*     */     
/*  79 */     boolean save = this.posterService.save(poster);
/*     */     
/*  81 */     return success(Boolean.valueOf(save));
/*     */   }

/*     */   @RequiresRoles("Admin")
/*     */   @PostMapping({"/state"})
/*     */   public R insert(Integer id, Integer state) {
/*  86 */     Poster poster = (Poster)this.posterService.getById(id);
/*  87 */     poster.setState(state);
/*  88 */     boolean save = this.posterService.saveOrUpdate(poster);
/*  89 */     return success(Boolean.valueOf(save));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @PutMapping
/*     */   public R update(@RequestBody Poster poster) {
/* 100 */     return success(Boolean.valueOf(this.posterService.updateById(poster)));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @DeleteMapping
/*     */   public R delete(@RequestParam("id") Integer id) {
/* 111 */     return success(Boolean.valueOf(this.posterService.removeById(id)));
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\PosterController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */