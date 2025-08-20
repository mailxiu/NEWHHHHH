/*     */ package com.bss.controller;
/*     */ 
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.baomidou.mybatisplus.core.metadata.IPage;
/*     */ import com.baomidou.mybatisplus.extension.api.ApiController;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
/*     */ import com.bss.entity.Grade;
/*     */ import com.bss.entity.GradeVo;
/*     */ import com.bss.entity.User;
/*     */ import com.bss.service.GradeService;
/*     */ import java.io.Serializable;
/*     */ import java.util.List;
/*     */ import javax.annotation.Resource;
/*     */ import javax.servlet.http.HttpSession;
/*     */ import org.apache.shiro.authz.annotation.RequiresPermissions;
/*     */ import org.apache.shiro.authz.annotation.RequiresRoles;
import org.slf4j.Logger;
/*     */ import org.slf4j.LoggerFactory;
/*     */ import org.springframework.web.bind.annotation.DeleteMapping;
/*     */ import org.springframework.web.bind.annotation.GetMapping;
/*     */ import org.springframework.web.bind.annotation.PathVariable;
/*     */ import org.springframework.web.bind.annotation.PostMapping;
/*     */ import org.springframework.web.bind.annotation.RequestBody;
/*     */ import org.springframework.web.bind.annotation.RequestMapping;
/*     */ import org.springframework.web.bind.annotation.RequestParam;
/*     */ import org.springframework.web.bind.annotation.RestController;
/*     */ 
/*     */ @RestController
/*     */ @RequestMapping({"grade"})
/*     */ public class GradeController
/*     */   extends ApiController {
/*  33 */   private static final Logger log = LoggerFactory.getLogger(com.bss.controller.GradeController.class);
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private GradeService gradeService;
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/list"})
/*     */   public R selectAll(String merchant) {
/*  51 */     List<Grade> list = this.gradeService.list((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("state", Integer.valueOf(1)));
/*     */     
/*  53 */     return success(list);
/*     */   }
/*     */   
/*     */   @GetMapping
/*     */   public R selectAll(Page<Grade> page, Grade grade) {
/*  58 */     return success(this.gradeService.page((IPage)page, (Wrapper)new QueryWrapper(grade)));
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
/*  69 */     return success(this.gradeService.getById(id));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @PostMapping
/*     */   public R insert(@RequestBody Grade grade) {
/*  80 */     return success(Boolean.valueOf(this.gradeService.save(grade)));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @RequiresRoles("Admin")
/*     */   @PostMapping({"/update"})
/*     */   public R update(GradeVo gradeVo, HttpSession session) {
/*  93 */     User user = (User)session.getAttribute("user");
/*     */     
/*  95 */     if (user == null) {
/*  96 */       return success(Boolean.valueOf(false)).setMsg("修改失败,权限验证失败").setCode(101L);
/*     */     }
/*     */     
/*  99 */     Grade grade = new Grade();
/*     */     
/* 101 */     if (gradeVo.getId().intValue() == 0) {
/* 102 */       grade.setId(Integer.valueOf(0));
/* 103 */       grade.setMerchant(user.getMerchant());
/* 104 */       grade.setState(Integer.valueOf(1));
/*     */     } else {
/* 106 */       grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("id", gradeVo.getId())).eq("merchant", user.getMerchant()));
/*     */     } 
/*     */     
/* 109 */     if (grade == null) {
/* 110 */       return success(Boolean.valueOf(false)).setMsg("修改失败,等级查询失败").setCode(101L);
/*     */     }
/*     */     
/* 113 */     grade.setName(gradeVo.getName());
/* 114 */     grade.setSort(gradeVo.getSort());
/* 115 */     grade.setPrice(gradeVo.getPrice());
/* 116 */     grade.setGain(gradeVo.getGain());
/* 117 */     grade.setTotal(gradeVo.getTotal());
/* 118 */     grade.setPresent(gradeVo.getPresent());
/* 119 */     grade.setDirectSpread(gradeVo.getDirectSpread());
/* 120 */     grade.setIndirectSpread(gradeVo.getIndirectSpread());
/* 121 */     grade.setPeriod(gradeVo.getPeriod());
/* 122 */     grade.setPeriodRefer(gradeVo.getPeriodRefer());
/*     */     
/* 124 */     boolean update = this.gradeService.saveOrUpdate(grade);
/*     */     
/* 126 */     return success(Boolean.valueOf(update)).setMsg("修改成功");
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @PostMapping({"/updateState"})
/*     */   public R updateState(@RequestParam("idList") List<Long> idList, Integer state, HttpSession session) {
/* 138 */     User user = (User)session.getAttribute("user");
/*     */     
/* 140 */     if (user == null) {
/* 141 */       return success(Boolean.valueOf(false)).setMsg("修改失败,权限验证失败").setCode(101L);
/*     */     }
/*     */     
/* 144 */     for (int i = 0; i < idList.size(); i++) {
/*     */       
/* 146 */       Grade grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("id", idList.get(i))).eq("merchant", user.getMerchant()));
/*     */       
/* 148 */       grade.setState(state);
/*     */       
/* 150 */       boolean update = this.gradeService.saveOrUpdate(grade);
/*     */       
/* 152 */       log.info("商户：{}，等级：{}，修改状态：{}", new Object[] { user.getMerchant(), grade.getSort(), Boolean.valueOf(update) });
/*     */     } 
/*     */ 
/*     */     
/* 156 */     return success(Boolean.valueOf(true));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @DeleteMapping({"/del"})
/*     */   public R delete(@RequestParam("id") Integer id) {
/* 169 */     return success(Boolean.valueOf(this.gradeService.removeById(id)));
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\GradeController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */