/*     */ package com.bss.controller;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.baomidou.mybatisplus.extension.api.ApiController;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.bss.entity.Category;
/*     */ import com.bss.entity.CategoryVo;
/*     */ import com.bss.entity.User;
/*     */ import com.bss.service.CategoryService;
/*     */ import com.bss.service.impl.ProjectServiceImpl;
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
/*     */ import org.springframework.web.bind.annotation.PutMapping;
/*     */ import org.springframework.web.bind.annotation.RequestBody;
/*     */ import org.springframework.web.bind.annotation.RequestMapping;
/*     */ import org.springframework.web.bind.annotation.RequestParam;
/*     */ import org.springframework.web.bind.annotation.RestController;
/*     */ 
/*     */ @RestController
/*     */ @RequestMapping({"category"})
/*     */ public class CategoryController extends ApiController {
/*  30 */   private static final Logger log = LoggerFactory.getLogger(com.bss.controller.CategoryController.class);
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private CategoryService categoryService;
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private ProjectServiceImpl projectService;
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping
/*     */   public R selectAll(String merchant) {
/*  51 */     Category category = new Category();
/*     */     
/*  53 */     category.setName("全部回收系列");
/*  54 */     category.setId(Integer.valueOf(0));
/*  55 */     category.setState(Integer.valueOf(1));
/*     */     
/*  57 */     List<Category> list = this.categoryService.list((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("state", Integer.valueOf(1)));
/*     */     
/*  59 */     list.add(0, category);
/*     */     
/*  61 */     return success(list);
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
/*  72 */     return success(this.categoryService.getById(id));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/add"})
/*     */   public R add(CategoryVo categoryVo, HttpSession session) {
/*  84 */     User user = (User)session.getAttribute("user");
/*     */     
/*  86 */     Category category = new Category();
/*  87 */     category.setId(Integer.valueOf(0));
/*  88 */     category.setMerchant(user.getMerchant());
/*  89 */     category.setSort(categoryVo.getSort());
/*  90 */     category.setName(categoryVo.getName());
/*  91 */     category.setImage(categoryVo.getImage());
/*  92 */     category.setState(categoryVo.getState());
/*     */     
/*  94 */     boolean save = this.categoryService.save(category);
/*     */     
/*  96 */     return success(Boolean.valueOf(save));
/*     */   }
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/update"})
/*     */   public R update(CategoryVo categoryVo) {
/* 103 */     Category category = (Category)this.categoryService.getById(categoryVo.getId());
/*     */     
/* 105 */     category.setSort(categoryVo.getSort());
/* 106 */     category.setName(categoryVo.getName());
/* 107 */     category.setImage(categoryVo.getImage());
/* 108 */     category.setState(categoryVo.getState());
/*     */     
/* 110 */     boolean save = this.categoryService.saveOrUpdate(category);
/*     */     
/* 112 */     return success(Boolean.valueOf(save));
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
/*     */   @PostMapping({"/update_state"})
/*     */   public R update_state(@RequestParam("idList") List<Long> idList, String state) {
/* 125 */     Integer u_state = Integer.valueOf(1);
/*     */     
/*     */     try {
/* 128 */       u_state = Integer.valueOf(state);
/* 129 */     } catch (Exception e) {
/* 130 */       return success(Integer.valueOf(0)).setMsg("更新失败,状态码异常").setCode(101L);
/*     */     } 
/*     */     
/* 133 */     int success = 0;
/*     */     
/* 135 */     for (int i = 0; i < idList.size(); i++) {
/*     */       
/* 137 */       Category category = (Category)this.categoryService.getOne((Wrapper)(new QueryWrapper()).eq("id", idList.get(i)));
/*     */       
/* 139 */       category.setState(u_state);
/*     */       
/* 141 */       boolean b = this.categoryService.saveOrUpdate(category);
/*     */       
/* 143 */       if (b) {
/* 144 */         success++;
/*     */       }
/*     */     } 
/*     */ 
/*     */ 
/*     */     
/* 150 */     if (success != idList.size()) {
/* 151 */       return success(Integer.valueOf(success)).setMsg("存在错误").setCode(102L);
/*     */     }
/*     */     
/* 154 */     return success(Integer.valueOf(success)).setMsg("修改成功");
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PutMapping
/*     */   public R update(@RequestBody Category category) {
/* 165 */     return success(Boolean.valueOf(this.categoryService.updateById(category)));
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
/*     */   @DeleteMapping({"/del"})
/*     */   public R delete(@RequestParam("id") Integer id, HttpSession session) {
/* 178 */     User user = (User)session.getAttribute("user");
/*     */ 
/*     */     
/* 181 */     int count = this.projectService.count((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("cid", id));
/*     */     
/* 183 */     if (count > 0) {
/* 184 */       return failed("该类目下存在项目");
/*     */     }
/*     */ 
/*     */     
/* 188 */     return success(Boolean.valueOf(this.categoryService.removeById(id)));
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\CategoryController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */