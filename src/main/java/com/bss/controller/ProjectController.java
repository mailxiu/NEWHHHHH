/*     */ package com.bss.controller;
/*     */ import com.alibaba.fastjson.JSON;
/*     */ import com.alibaba.fastjson.JSONArray;
/*     */ import com.alibaba.fastjson.JSONObject;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
/*     */ import com.baomidou.mybatisplus.core.metadata.IPage;
/*     */ import com.baomidou.mybatisplus.extension.api.ApiController;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
/*     */ import com.bss.entity.Grade;
/*     */ import com.bss.entity.Member;
/*     */ import com.bss.entity.Project;
/*     */ import com.bss.entity.ProjectVo;
/*     */ import com.bss.entity.User;
/*     */ import com.bss.service.impl.GradeServiceImpl;
/*     */ import com.bss.service.impl.MemberServiceImpl;
/*     */ import com.bss.service.impl.ProjectServiceImpl;
/*     */ import java.io.Serializable;
/*     */ import java.math.RoundingMode;
/*     */ import java.text.DecimalFormat;
/*     */ import java.util.List;
/*     */ import javax.annotation.Resource;
/*     */ import javax.servlet.http.HttpSession;
/*     */ import com.bss.service.impl.RecordServiceImpl;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.slf4j.Logger;
/*     */ import org.slf4j.LoggerFactory;
/*     */ import org.springframework.web.bind.annotation.*;
/*     */
/*     */
/*     */
/*     */
/*     */
/*     */

/*     */
/*     */ @RestController
/*     */ @RequestMapping({"project"})
/*     */ public class ProjectController extends ApiController {
/*  39 */   private static final Logger log = LoggerFactory.getLogger(com.bss.controller.ProjectController.class);
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private ProjectServiceImpl projectService;
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private RecordServiceImpl recordService;
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private MemberServiceImpl memberService;
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private GradeServiceImpl gradeService;
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping
/*     */   public R selectAll(Page<Project> page, Project project) {
/*  67 */     return success(((Page)this.projectService.page((IPage)page, (Wrapper)new QueryWrapper(project))).getRecords());
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @RequestMapping({"/list"})
/*     */   public R getList(@RequestParam(name = "merchant") String merchant, @RequestParam(name = "cid") Integer cid, @RequestParam(name = "uid", defaultValue = "") Integer uid, @RequestParam(name = "pageIndex") Integer pageIndex) {
/*  76 */     double gain = 1.0D;
/*     */     
/*  78 */     if (uid != null && !uid.equals("")) {
/*     */       
/*  80 */       Member member = (Member)this.memberService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("uid", uid));
/*     */       
/*  82 */       Grade grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("sort", member.getPartner()));
/*     */       
/*  84 */       gain = grade.getGain().doubleValue();
/*     */     } 
/*     */     
/*  87 */     QueryWrapper queryWrapper = new QueryWrapper();
/*  88 */     queryWrapper.eq("merchant", merchant);
/*     */     
/*  90 */     if (!cid.equals(Integer.valueOf(0))) {
/*  91 */       queryWrapper.eq("cid", cid);
/*     */     }
/*     */     
/*  94 */     queryWrapper.ne("state", "不回收");
/*     */     
/*  96 */     queryWrapper.orderByDesc("sort");
/*     */     
/*  98 */     IPage<Project> iPage = this.projectService.page((IPage)new Page(pageIndex.intValue(), 12L), (Wrapper)queryWrapper);
/*     */     
/* 100 */     JSONArray array = (JSONArray)JSON.toJSON(iPage.getRecords());
/*     */     
/* 102 */     DecimalFormat format = new DecimalFormat("0.00");
/*     */     
/* 104 */     format.setRoundingMode(RoundingMode.DOWN);
/*     */     
/* 106 */     for (int i = 0; i < array.size(); i++) {
/*     */       
/* 108 */       JSONObject o = array.getJSONObject(i);
/*     */       
/* 110 */       Double n_points = Double.valueOf(o.getDouble("points").doubleValue() * gain);
/*     */       
/* 112 */       String str = format.format(n_points);
/*     */       
/* 114 */       o.put("points", str);
/*     */     } 
/*     */     
/* 117 */     return success(array);
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
/*     */ 
/*     */ 
/*     */   
/*     */   @RequestMapping({"/price"})
/*     */   public R getPrice(@RequestParam(name = "merchant") String merchant, @RequestParam(name = "cid") Integer cid, @RequestParam(name = "uid", defaultValue = "") Integer uid, @RequestParam(name = "pageIndex") Integer pageIndex) {
/* 136 */     List<Grade> gradeList = this.gradeService.list((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).orderByAsc("sort"));
/*     */     
/* 138 */     Double grade_max = ((Grade)gradeList.get(gradeList.size() - 1)).getGain();
/*     */     
/* 140 */     QueryWrapper queryWrapper = new QueryWrapper();
/* 141 */     queryWrapper.eq("merchant", merchant);
/*     */     
/* 143 */     if (!cid.equals(Integer.valueOf(0))) {
/* 144 */       queryWrapper.eq("cid", cid);
/*     */     }
/* 146 */     queryWrapper.ne("state", "不回收");
/*     */     
/* 148 */     IPage<Project> iPage = this.projectService.page((IPage)new Page(pageIndex.intValue(), 12L), (Wrapper)queryWrapper);
/*     */     
/* 150 */     JSONArray array = (JSONArray)JSON.toJSON(iPage.getRecords());
/*     */     
/* 152 */     DecimalFormat format = new DecimalFormat("0.00");
/*     */     
/* 154 */     format.setRoundingMode(RoundingMode.DOWN);
/*     */     
/* 156 */     for (int i = 0; i < array.size(); i++) {
/*     */       
/* 158 */       JSONObject o = array.getJSONObject(i);
/*     */       
/* 160 */       String points = format.format(o.getDouble("points"));
/*     */       
/* 162 */       Double n_points = Double.valueOf(o.getDouble("points").doubleValue() * grade_max.doubleValue());
/*     */       
/* 164 */       String points_max = format.format(n_points);
/*     */       
/* 166 */       o.put("points", points);
/*     */       
/* 168 */       o.put("points_max", points_max);
/*     */     } 
/*     */     
/* 171 */     return success(array);
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
/* 182 */     return success(this.projectService.getById(id));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping({"/qrCode"})
/*     */   public R selectOneByQrCodee(String qr_code, String merchant) {
/* 190 */     List<Project> list = this.projectService.list((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("state", "回收中")).ne("pattern", ""));
/*     */     
/* 192 */     Project project = null;
/*     */     
/* 194 */     for (int i = 0; i < list.size(); i++) {
/*     */       
/* 196 */       if (qr_code.matches(((Project)list.get(i)).getPattern())) {
/* 197 */         project = list.get(i);
/*     */         
/*     */         break;
/*     */       } 
/*     */     } 
/* 202 */     if (project != null) {
/* 203 */       return success(project);
/*     */     }
/*     */     
/* 206 */     return success(null).setMsg("未匹配该二维码").setCode(101L);
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping({"/barCode"})
/*     */   public R selectOneByBarCode(String code, String merchant) {
/* 218 */     Project project = (Project)this.projectService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("bar_code", code)).eq("merchant", merchant));
/*     */     
/* 220 */     if (project == null) {
/*     */       
/* 222 */       project = new Project();
/* 223 */       project.setCid("0");
/* 224 */       project.setImage("https://smyxcx.oss-accelerate.aliyuncs.com/smy/logo.jpg");
/* 225 */       project.setMerchant(merchant);
/* 226 */       project.setBarCode(code);
/* 227 */       project.setState("待审核");
/* 228 */       project.setPoints(Double.valueOf(0.0D));
/* 229 */       project.setChecking(Boolean.valueOf(false));
/* 230 */       project.setName("未知");
/*     */       
/* 232 */       this.projectService.saveOrUpdate(project);
/*     */       
/* 234 */       return success("此条码，暂不回收").setCode(101L);
/*     */     } 
/*     */     
/* 237 */     return success(project);
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
/*     */   public R insert(ProjectVo projectVo, HttpSession session) {
/* 249 */     User user = (User)session.getAttribute("user");
/*     */     
/* 251 */     Project o = (Project)this.projectService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("bar_code", projectVo.getBarCode()));
/*     */     
/* 253 */     if (o != null) {
/* 254 */       return success("添加失败,数据已添加").setCode(101L);
/*     */     }
/*     */     
/* 257 */     Project project = new Project();
/*     */     
/* 259 */     project.setId(Integer.valueOf(0));
/* 260 */     project.setMerchant(user.getMerchant());
/* 261 */     project.setCid(projectVo.getCid());
/* 262 */     project.setSort(projectVo.getSort());
/* 263 */     project.setBarCode(projectVo.getBarCode());
/* 264 */     project.setName(projectVo.getName());
/* 265 */     project.setImage(projectVo.getImage());
/* 266 */     project.setPoints(projectVo.getPoints());
/* 267 */     project.setChecking(projectVo.getChecking());
/* 268 */     project.setMixed(projectVo.getMixed());
/* 269 */     project.setRemarks(projectVo.getRemarks());
/* 270 */     project.setState("回收中");
/* 271 */     boolean save = this.projectService.save(project);
/*     */     
/* 273 */     return success(Boolean.valueOf(save));
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
/*     */   public R update(ProjectVo projectVo, HttpSession session) {
/* 286 */     Project project = (Project)this.projectService.getById(projectVo.getId());
/*     */     
/* 288 */     project.setCid(projectVo.getCid());
/* 289 */     project.setSort(projectVo.getSort());
/* 290 */     project.setBarCode(projectVo.getBarCode());
/* 291 */     project.setName(projectVo.getName());
/* 292 */     project.setImage(projectVo.getImage());
/* 293 */     project.setPoints(projectVo.getPoints());
/* 294 */     project.setPattern(projectVo.getPattern());
/* 295 */     project.setChecking(projectVo.getChecking());
/* 296 */     project.setMixed(projectVo.getMixed());
/* 297 */     project.setRemarks(projectVo.getRemarks());
/* 298 */     project.setState(projectVo.getState());
/*     */     
/* 300 */     boolean update = this.recordService.update((Wrapper)((UpdateWrapper)((UpdateWrapper)((UpdateWrapper)((UpdateWrapper)((UpdateWrapper)(new UpdateWrapper()).eq("merchant", project.getMerchant())).eq("code", project.getBarCode())).eq("state", "审核中")).set("name", project.getName())).set("image", project.getImage())).set("points", project.getPoints()));
/*     */     
/* 302 */     boolean save = this.projectService.saveOrUpdate(project);
/*     */     
/* 304 */     return success(Boolean.valueOf(save));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @PutMapping
/*     */   public R update(@RequestBody Project project) {
/* 316 */     return success(Boolean.valueOf(this.projectService.updateById(project)));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @PostMapping({"/state_all"})
/*     */   public R state_all(@RequestParam("idList") List<Long> idList, String state) {
/* 328 */     System.out.println(idList.size());
/* 329 */     String n_state = "";
/*     */     
/* 331 */     if (state.equals("1")) {
/* 332 */       n_state = "回收中";
/*     */     } else {
/* 334 */       n_state = "不回收";
/*     */     } 
/*     */     
/* 337 */     int success = 0;
/*     */     
/* 339 */     for (int i = 0; i < idList.size(); i++) {
/*     */       
/* 341 */       Project project = (Project)this.projectService.getOne((Wrapper)(new QueryWrapper()).eq("id", idList.get(i)));
/*     */       
/* 343 */       project.setState(n_state);
/*     */       
/* 345 */       System.out.println(project);
/*     */       
/* 347 */       boolean b = this.projectService.saveOrUpdate(project);
/*     */       
/* 349 */       if (b) {
/* 350 */         success++;
/*     */       }
/*     */     } 
/*     */     
/* 354 */     JSONObject data = new JSONObject();
/*     */     
/* 356 */     data.put("state:", state);
/* 357 */     data.put("total:", Integer.valueOf(idList.size()));
/* 358 */     data.put("success:", Integer.valueOf(success));
/* 359 */     data.put("fail:", Integer.valueOf(idList.size() - success));
/*     */     
/* 361 */     return success(data).setMsg(data.toString());
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @DeleteMapping({"/del"})
/*     */   public R delete(@RequestParam("idList") List<Long> idList) {
/* 373 */     if (idList.size() >= 5) {
/* 374 */       return success(null).setMsg("当前操作存在风险,拒绝执行").setCode(101L);
/*     */     }
/*     */     
/* 377 */     return success(Boolean.valueOf(this.projectService.removeByIds(idList)));
/*     */   }
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @DeleteMapping({"/delOne"})
/*     */   public R delOne(@RequestParam("id") Integer id) {
/* 383 */     return success(Boolean.valueOf(this.projectService.removeById(id)));
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\ProjectController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */