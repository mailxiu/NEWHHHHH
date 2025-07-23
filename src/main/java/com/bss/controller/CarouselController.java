/*     */ package com.bss.controller;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.api.ApiController;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
/*     */ import com.bss.entity.Carousel;
/*     */ import com.bss.entity.User;
/*     */ import com.bss.service.CarouselService;
/*     */ import java.io.File;
/*     */ import java.io.Serializable;
/*     */ import java.util.List;
/*     */ import javax.annotation.Resource;
/*     */ import javax.servlet.http.HttpSession;
/*     */ import org.slf4j.Logger;
/*     */ import org.slf4j.LoggerFactory;
/*     */ import org.springframework.web.bind.annotation.DeleteMapping;
/*     */ import org.springframework.web.bind.annotation.GetMapping;
/*     */ import org.springframework.web.bind.annotation.PathVariable;
/*     */ import org.springframework.web.bind.annotation.PostMapping;
/*     */ import org.springframework.web.bind.annotation.RequestMapping;
/*     */ import org.springframework.web.bind.annotation.RequestParam;
/*     */ import org.springframework.web.bind.annotation.RestController;
/*     */ 
/*     */ @RestController
/*     */ @RequestMapping({"carousel"})
/*     */ public class CarouselController extends ApiController {
/*  28 */   private static final Logger log = LoggerFactory.getLogger(com.bss.controller.CarouselController.class);
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private CarouselService carouselService;
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping
/*     */   public R selectAll(Page<Carousel> page, Carousel carousel) {
/*  47 */     return success(this.carouselService.page((IPage)page, (Wrapper)new QueryWrapper(carousel)));
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
/*  58 */     return success(this.carouselService.getById(id));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/add"})
/*     */   public R insert(Integer state, Integer sort, String respond, String event, String imageUri, HttpSession session) {
/*  69 */     User user = (User)session.getAttribute("user");
/*     */     
/*  71 */     Carousel carousel = new Carousel();
/*  72 */     carousel.setId(Integer.valueOf(0));
/*  73 */     carousel.setMerchant(user.getMerchant());
/*  74 */     carousel.setImageUri(imageUri);
/*  75 */     carousel.setState(state);
/*  76 */     carousel.setSort(sort);
/*  77 */     carousel.setEvent(event);
/*  78 */     carousel.setRespond(respond);
/*     */     
/*  80 */     boolean save = this.carouselService.save(carousel);
/*  81 */     return success(Boolean.valueOf(save));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/state"})
/*     */   public R insert(Integer id, Integer state) {
/*  92 */     Carousel carousel = (Carousel)this.carouselService.getById(id);
/*  93 */     carousel.setState(state);
/*  94 */     boolean save = this.carouselService.saveOrUpdate(carousel);
/*  95 */     return success(Boolean.valueOf(save));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/sort"})
/*     */   public R sort(Integer id, Integer sort) {
/* 106 */     Carousel carousel = (Carousel)this.carouselService.getById(id);
/* 107 */     carousel.setSort(sort);
/* 108 */     boolean save = this.carouselService.saveOrUpdate(carousel);
/* 109 */     return success(Boolean.valueOf(save));
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
/*     */   @DeleteMapping
/*     */   public R delete(@RequestParam("id") Integer id) {
/* 122 */     Carousel carousel = (Carousel)this.carouselService.getById(id);
/*     */     
/* 124 */     String str = "https://img.openk.cn/express/operate";
/*     */ 
/*     */     
/* 127 */     if (carousel.getImageUri().indexOf(str) != -1) {
/*     */       
/* 129 */       List<Carousel> list = this.carouselService.list((Wrapper)(new QueryWrapper()).eq("image_uri", carousel.getImageUri()));
/*     */       
/* 131 */       if (list.size() == 1) {
/* 132 */         String dir = carousel.getImageUri().substring(str.length());
/*     */         
/* 134 */         File file = new File("/www/wwwroot/image/express/operate" + dir);
/*     */         
/* 136 */         if (file.delete()) {
/* 137 */           log.info("图片删除成功...");
/*     */         } else {
/* 139 */           log.info("图片删除失败==>{}", carousel.getImageUri());
/*     */         } 
/*     */       } else {
/* 142 */         log.info("图片保留,存在其他项目引用==>{}", carousel.getImageUri());
/*     */       } 
/*     */     } 
/*     */     
/* 146 */     return success(Boolean.valueOf(this.carouselService.removeById(id)));
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\CarouselController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */