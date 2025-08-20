/*     */ package com.bss.controller;
/*     */ 
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.bss.entity.Category;
/*     */ import com.bss.entity.Grade;
/*     */ import com.bss.entity.Project;
/*     */ import com.bss.entity.User;
/*     */ import com.bss.service.impl.CategoryServiceImpl;
/*     */ import com.bss.service.impl.GradeServiceImpl;
/*     */ import com.bss.service.impl.ProjectServiceImpl;
/*     */ import com.bss.utils.R;
/*     */ import java.util.List;
/*     */ import javax.annotation.Resource;
/*     */ import javax.servlet.http.HttpSession;
/*     */ import org.apache.shiro.authz.annotation.RequiresRoles;
import org.slf4j.Logger;
/*     */ import org.slf4j.LoggerFactory;
/*     */ import org.springframework.web.bind.annotation.RequestMapping;
/*     */ import org.springframework.web.bind.annotation.RestController;
/*     */ 
/*     */ 
/*     */ @RestController
/*     */ @RequestMapping({"docking"})
/*     */ public class DockingController
/*     */ {
/*  26 */   private static final Logger log = LoggerFactory.getLogger(com.bss.controller.DockingController.class);
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private CategoryServiceImpl categoryService;
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private ProjectServiceImpl projectService;
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private GradeServiceImpl gradeService;
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @RequestMapping({"/category"})
/*     */   public R docking_category(HttpSession session) {
/*  49 */     User user = (User)session.getAttribute("user");
/*     */ 
/*     */     
/*  52 */     boolean remove = this.categoryService.remove((Wrapper)(new QueryWrapper()).eq("merchant", user.getMerchant()));
/*     */     
/*  54 */     log.info("清空之前的类目表：{}", Boolean.valueOf(remove));
/*     */ 
/*     */     
/*  57 */     List<Category> category_list = this.categoryService.list((Wrapper)(new QueryWrapper()).eq("merchant", Integer.valueOf(100000)));
/*     */     
/*  59 */     category_list.forEach(category -> {
/*     */           category.setId(Integer.valueOf(0));
/*     */ 
/*     */           
/*     */           category.setMerchant(user.getMerchant());
/*     */           
/*     */           this.categoryService.save(category);
/*     */         });
/*     */     
/*  68 */     return R.success();
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @RequestMapping({"/project"})
/*     */   public R docking_project(HttpSession session) {
/*  78 */     User user = (User)session.getAttribute("user");
/*     */ 
/*     */     
/*  81 */     boolean remove = this.projectService.remove((Wrapper)(new QueryWrapper()).eq("merchant", user.getMerchant()));
/*     */ 
/*     */     
/*  84 */     List<Category> category_list = this.categoryService.list((Wrapper)(new QueryWrapper()).eq("merchant", Integer.valueOf(100000)));
/*     */ 
/*     */     
/*  87 */     category_list.forEach(category -> {
/*     */           List<Project> list = this.projectService.list((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", Integer.valueOf(100000))).eq("cid", category.getId()));
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */           
/*     */           Category t = (Category)this.categoryService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("name", category.getName()));
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */           
/*     */           if (list.size() != 0) {
/*     */             (new Thread()).start();
/*     */           }
/*     */         });
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 115 */     return R.success();
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @RequestMapping({"/grade"})
/*     */   public R docking_grade(HttpSession session) {
/* 127 */     User user = (User)session.getAttribute("user");
/*     */ 
/*     */     
/* 130 */     boolean remove = this.gradeService.remove((Wrapper)(new QueryWrapper()).eq("merchant", user.getMerchant()));
/*     */ 
/*     */     
/* 133 */     log.info("清空之前的级别表：{}", Boolean.valueOf(remove));
/*     */ 
/*     */     
/* 136 */     List<Grade> list = this.gradeService.list((Wrapper)(new QueryWrapper()).eq("merchant", Integer.valueOf(100000)));
/*     */     
/* 138 */     list.forEach(grade -> {
/*     */           grade.setId(Integer.valueOf(0));
/*     */ 
/*     */           
/*     */           grade.setMerchant(user.getMerchant());
/*     */           
/*     */           this.gradeService.save(grade);
/*     */         });
/*     */     
/* 147 */     return R.success();
/*     */   }
/*     */ }

