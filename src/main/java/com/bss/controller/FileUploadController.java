/*     */ package com.bss.controller;
/*     */ import com.alibaba.fastjson.JSONObject;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.bss.entity.SystemConfig;
/*     */ import com.bss.service.impl.SystemConfigServiceImpl;
import com.bss.utils.R;
/*     */ import java.io.File;
/*     */ import java.io.IOException;
/*     */ import java.util.UUID;
/*     */ import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
/*     */ import org.apache.commons.io.FilenameUtils;
/*     */ import org.slf4j.Logger;
/*     */ import org.slf4j.LoggerFactory;
/*     */ import org.springframework.web.bind.annotation.PostMapping;
/*     */ import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
/*     */ 
/*     */ @RestController
/*     */ public class FileUploadController {
/*  19 */   private static final Logger log = LoggerFactory.getLogger(com.bss.controller.FileUploadController.class);
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private SystemConfigServiceImpl systemConfigService;
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/upload"})
/*     */   public R upload(MultipartFile uploadFile, HttpServletRequest req) throws IOException {
/*  30 */     SystemConfig system = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/*  32 */     log.info("上传图片：{}", "收到图片上传请求...");
/*     */     
/*  34 */     String path = system.getGalleryRoute() + "/portrait";
/*     */ 
/*     */     
/*  37 */     String name = UUID.randomUUID().toString().replaceAll("-", "");
/*     */     
/*  39 */     String ext = FilenameUtils.getExtension(uploadFile.getOriginalFilename());
/*     */     
/*  41 */     String fileName = name + "." + ext;
/*     */     
/*  43 */     File dir = new File(path, fileName);
/*     */ 
/*     */ 
/*     */ 
/*     */     
/*  48 */     if (!dir.exists()) {
/*  49 */       dir.mkdirs();
/*     */     }
/*     */     
/*  52 */     if (!uploadFile.isEmpty()) {
/*     */       
/*  54 */       uploadFile.transferTo(dir);
/*     */       
/*  56 */       String url = system.getGalleryUrl() + "/portrait/" + fileName;
/*     */       
/*  58 */       log.info("上传图片：{}", "完成图片上传处理...");
/*     */       
/*  60 */       return R.success(url);
/*     */     } 
/*     */     
/*  63 */     log.info("上传图片异常:{}", "上传文件为空");
/*  64 */     return R.fail("上传文件为空");
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/upload_project"})
/*     */   public R upload_project(MultipartFile uploadFile, HttpServletRequest req) throws IOException {
/*  73 */     SystemConfig system = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/*  75 */     log.info("上传图片：{}", "收到图片上传请求...");
/*     */     
/*  77 */     String path = system.getGalleryRoute() + "/project";
/*     */ 
/*     */     
/*  80 */     String name = UUID.randomUUID().toString().replaceAll("-", "");
/*     */     
/*  82 */     String ext = FilenameUtils.getExtension(uploadFile.getOriginalFilename());
/*     */     
/*  84 */     String fileName = name + "." + ext;
/*     */     
/*  86 */     File dir = new File(path, fileName);
/*     */ 
/*     */ 
/*     */ 
/*     */     
/*  91 */     if (!dir.exists()) {
/*  92 */       dir.mkdirs();
/*     */     }
/*     */     
/*  95 */     if (!uploadFile.isEmpty()) {
/*     */       
/*  97 */       uploadFile.transferTo(dir);
/*     */       
/*  99 */       String url = system.getGalleryUrl() + "/project/" + fileName;
/*     */       
/* 101 */       log.info("上传图片：{}", "完成图片上传处理...");
/*     */       
/* 103 */       return R.success(url);
/*     */     } 
/*     */     
/* 106 */     log.info("上传图片异常:{}", "上传文件为空");
/* 107 */     return R.fail("上传文件为空");
/*     */   }
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/upload_operate"})
/*     */   public R upload_operate(MultipartFile uploadFile, HttpServletRequest req) throws IOException {
/* 114 */     SystemConfig system = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/* 116 */     log.info("上传图片：{}", "收到图片上传请求...");
/*     */     
/* 118 */     String path = system.getGalleryRoute() + "/operate";
/*     */ 
/*     */     
/* 121 */     String name = UUID.randomUUID().toString().replaceAll("-", "");
/*     */     
/* 123 */     String ext = FilenameUtils.getExtension(uploadFile.getOriginalFilename());
/*     */     
/* 125 */     String fileName = name + "." + ext;
/*     */     
/* 127 */     File dir = new File(path, fileName);
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 132 */     if (!dir.exists()) {
/* 133 */       dir.mkdirs();
/*     */     }
/*     */     
/* 136 */     if (!uploadFile.isEmpty()) {
/*     */       
/* 138 */       uploadFile.transferTo(dir);
/*     */       
/* 140 */       String url = system.getGalleryUrl() + "/operate/" + fileName;
/*     */ 
/*     */ 
/*     */       
/* 144 */       log.info("上传图片：{}", "完成图片上传处理...");
/*     */       
/* 146 */       return R.success(url);
/*     */     } 
/*     */     
/* 149 */     log.info("上传图片异常:{}", "上传文件为空");
/* 150 */     return R.fail("上传文件为空");
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
/*     */   @PostMapping({"/upload_complaint"})
/*     */   public R upload_complaint(MultipartFile uploadFile, HttpServletRequest req) throws IOException {
/* 166 */     SystemConfig system = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/* 168 */     log.info("上传图片：{}", "收到图片上传请求...");
/*     */     
/* 170 */     String path = system.getGalleryRoute() + "/complaint";
/*     */ 
/*     */     
/* 173 */     String name = UUID.randomUUID().toString().replaceAll("-", "");
/*     */     
/* 175 */     String ext = FilenameUtils.getExtension(uploadFile.getOriginalFilename());
/*     */     
/* 177 */     String fileName = name + "." + ext;
/*     */     
/* 179 */     File dir = new File(path, fileName);
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 184 */     if (!dir.exists()) {
/* 185 */       dir.mkdirs();
/*     */     }
/*     */     
/* 188 */     if (!uploadFile.isEmpty()) {
/*     */       
/* 190 */       uploadFile.transferTo(dir);
/*     */       
/* 192 */       String url = system.getGalleryUrl() + "/complaint/" + fileName;
/*     */       
/* 194 */       log.info("上传图片：{}", "完成图片上传处理...");
/*     */       
/* 196 */       return R.success(url);
/*     */     } 
/*     */     
/* 199 */     log.info("上传图片异常:{}", "上传文件为空");
/* 200 */     return R.fail("上传文件为空");
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/upload_markdown"})
/*     */   public String upload_markdown(@RequestParam("editormd-image-file") MultipartFile uploadFile, HttpServletRequest req) throws IOException {
/* 208 */     SystemConfig system = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/* 210 */     log.info("上传图片：{}", "收到图片上传请求...");
/*     */     
/* 212 */     String path = system.getGalleryRoute() + "/article";
/*     */ 
/*     */     
/* 215 */     String name = UUID.randomUUID().toString().replaceAll("-", "");
/*     */     
/* 217 */     String ext = FilenameUtils.getExtension(uploadFile.getOriginalFilename());
/*     */     
/* 219 */     String fileName = name + "." + ext;
/*     */     
/* 221 */     File dir = new File(path, fileName);
/*     */     
/* 223 */     JSONObject res = new JSONObject();
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 228 */     if (!dir.exists()) {
/* 229 */       dir.mkdirs();
/*     */     }
/*     */     
/* 232 */     if (!uploadFile.isEmpty()) {
/*     */       
/* 234 */       uploadFile.transferTo(dir);
/*     */       
/* 236 */       String url = system.getGalleryUrl() + "/article/" + fileName;
/*     */       
/* 238 */       log.info("上传图片：{}", "完成图片上传处理...");
/*     */       
/* 240 */       res.put("url", url);
/* 241 */       res.put("success", Integer.valueOf(1));
/* 242 */       res.put("message", "upload success!");
/*     */       
/* 244 */       return res.toString();
/*     */     } 
/*     */     
/* 247 */     log.info("上传图片异常:{}", "上传文件为空");
/*     */     
/* 249 */     res.put("url", "");
/* 250 */     res.put("success", Integer.valueOf(0));
/* 251 */     res.put("message", "上传文件为空!");
/* 252 */     return res.toString();
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\FileUploadController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */