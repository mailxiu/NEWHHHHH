/*      */ package com.bss.controller;
/*      */ import cn.hutool.core.util.RandomUtil;
import com.alibaba.fastjson.JSON;
/*      */ import com.alibaba.fastjson.JSONArray;
/*      */ import com.alibaba.fastjson.JSONObject;
/*      */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*      */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*      */ import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
/*      */ import com.baomidou.mybatisplus.core.metadata.IPage;
/*      */ import com.baomidou.mybatisplus.extension.api.R;
/*      */ import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
/*      */ import com.bss.entity.Grade;
/*      */ import com.bss.entity.Member;
/*      */ import com.bss.entity.Project;
/*      */ import com.bss.entity.Record;
/*      */ import com.bss.entity.Settlement;
/*      */ import com.bss.entity.Stock;
/*      */ import com.bss.entity.User;
/*      */ import java.io.BufferedOutputStream;
/*      */ import java.io.OutputStream;
import java.io.PrintWriter;
/*      */ import java.io.Serializable;
/*      */ import java.math.BigDecimal;
/*      */ import java.math.RoundingMode;
/*      */ import java.text.DateFormat;
/*      */ import java.text.DecimalFormat;
/*      */ import java.text.NumberFormat;
/*      */ import java.text.SimpleDateFormat;
/*      */ import java.util.*;
/*      */
/*      */
/*      */
/*      */
/*      */
/*      */
/*      */ import java.util.concurrent.ConcurrentHashMap;
/*      */ import java.util.concurrent.CountDownLatch;
/*      */ import java.util.concurrent.locks.Lock;
/*      */ import java.util.concurrent.locks.ReentrantLock;
/*      */ import java.util.stream.Collectors;
/*      */ import javax.annotation.Resource;
/*      */ import javax.servlet.ServletOutputStream;
/*      */ import javax.servlet.http.HttpServletResponse;
/*      */ import javax.servlet.http.HttpSession;
/*      */ import com.bss.service.ProjectService;
import com.bss.service.impl.*;
import org.springframework.web.bind.annotation.*;
import com.baomidou.mybatisplus.extension.api.ApiController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static com.bss.utils.R.success;
/*      */
/*      */
/*      */
/*      */
/*      */

/*      */
/*      */ @RestController
/*      */ @RequestMapping({"record"})
/*      */ public class RecordController extends ApiController {
/*   53 */   private static final Logger log = LoggerFactory.getLogger(com.bss.controller.RecordController.class);
/*      */ 
/*      */   
///*      */   @Resource
///*      */   private SecurityManager securityManager;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private RecordServiceImpl recordService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private SettlementServiceImpl settlementService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private ProjectService projectService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private GradeServiceImpl gradeService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private UserServiceImpl userService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private MemberServiceImpl memberService;
/*      */   
/*      */   @Resource
/*      */   private StockServiceImpl stockService;
/*      */ 
/*      */   
/*      */   @GetMapping({"/list"})
/*      */   public R selectList(@RequestParam(name = "pageIndex") Integer pageIndex, String uid, String state) {
/*   89 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", uid));
/*      */     
/*   91 */     if (member == null) {
/*   92 */       log.info("查询会员为空：uid->{}", uid);
/*   93 */       return success(new ArrayList());
/*      */     } 
/*      */     
/*   96 */     QueryWrapper<Record> queryWrapper = new QueryWrapper();
/*      */     
/*   98 */     queryWrapper.eq("merchant", member.getMerchant());
/*   99 */     queryWrapper.eq("uid", uid);
/*  100 */     queryWrapper.eq("state", state);
/*      */     
/*  102 */     IPage<Record> iPage = this.recordService.page((IPage)new Page(pageIndex.intValue(), 12L), (Wrapper)queryWrapper);
/*      */     
/*  104 */     return success(iPage.getRecords());
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @GetMapping({"/sale"})
/*      */   public R sale(String merchant, String uid, String code, @RequestParam(name = "total", defaultValue = "1") Integer total) {
/*  119 */     Member member = (Member)this.memberService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("uid", uid));
/*      */     
/*  121 */     Calendar calendar = Calendar.getInstance();
/*      */ 
/*      */     
/*  124 */     Date update_time = calendar.getTime();
/*      */     
/*  126 */     if (member == null) {
/*  127 */       log.info("查询会员为空：uid->{}", uid);
/*  128 */       return failed("查询会员为空");
/*      */     } 
/*      */     
/*  131 */     Project project = (Project)this.projectService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", member.getMerchant())).eq("bar_code", code));
/*      */     
/*  133 */     if (project == null) {
/*  134 */       return failed("项目不存在");
/*      */     }
/*      */     
/*  137 */     if (!project.getState().equals("回收中")) {
/*  138 */       return failed("该商品厂家活动还未开启");
/*      */     }
/*      */     
/*  141 */     QueryWrapper<Record> countWrapper = new QueryWrapper();
/*  142 */     countWrapper.eq("merchant", member.getMerchant());
/*  143 */     countWrapper.eq("code", code);
/*  144 */     countWrapper.eq("uid", uid);
/*  145 */     countWrapper.eq("state", "审核中");
/*  146 */     countWrapper.eq("sale", Integer.valueOf(0));
/*      */     
/*  148 */     int count = this.recordService.count((Wrapper)countWrapper);
/*      */     
/*  150 */     if (total.intValue() > count) {
/*  151 */       return failed("销售数量异常");
/*      */     }
/*      */     
/*  154 */     UpdateWrapper<Record> updateWrapper = new UpdateWrapper();
/*  155 */     updateWrapper.set("sale", Integer.valueOf(1));
/*  156 */     updateWrapper.set("update_time", update_time);
/*      */     
/*  158 */     updateWrapper.eq("merchant", member.getMerchant());
/*  159 */     updateWrapper.eq("code", code);
/*  160 */     updateWrapper.eq("uid", uid);
/*  161 */     updateWrapper.eq("state", "审核中");
/*  162 */     updateWrapper.eq("sale", Integer.valueOf(0));
/*  163 */     updateWrapper.last("LIMIT " + total);
/*      */ 
/*      */     
/*  166 */     boolean update = this.recordService.update((Wrapper)updateWrapper);
/*      */     
/*  168 */     return success(Boolean.valueOf(update)).setMsg("出库成功，等待核销");
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @GetMapping({"/getList"})
/*      */   public R getList(@RequestParam(name = "pageIndex") Integer pageIndex, String uid, String state, @RequestParam(name = "sale", defaultValue = "0") Integer sale) {
/*  182 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", uid));
/*      */     
/*  184 */     if (member == null) {
/*  185 */       log.info("查询会员为空：uid->{}", uid);
/*  186 */       return success(new ArrayList());
/*      */     } 
/*      */     
/*  189 */     if (sale.intValue() == 1) {
/*  190 */       QueryWrapper<Record> queryWrapper = new QueryWrapper();
/*      */       
/*  192 */       queryWrapper.eq("merchant", member.getMerchant());
/*  193 */       queryWrapper.eq("uid", uid);
/*  194 */       queryWrapper.eq("state", state);
/*  195 */       queryWrapper.eq("sale", sale);
/*      */       
/*  197 */       IPage<Record> iPage1 = this.recordService.page((IPage)new Page(pageIndex.intValue(), 12L), (Wrapper)queryWrapper);
/*  198 */       return success(iPage1.getRecords());
/*      */     } 
/*      */     
/*  201 */     QueryWrapper<Record> saleWrapper = new QueryWrapper();
/*      */     
/*  203 */     saleWrapper.eq("merchant", member.getMerchant());
/*  204 */     saleWrapper.eq("uid", uid);
/*  205 */     saleWrapper.eq("state", state);
/*  206 */     saleWrapper.eq("sale", sale);
/*  207 */     saleWrapper.groupBy("code");
/*      */     
/*  209 */     IPage<Record> iPage = this.recordService.page((IPage)new Page(pageIndex.intValue(), 12L), (Wrapper)saleWrapper);
/*      */     
/*  211 */     List<Record> list = iPage.getRecords();
/*      */     
/*  213 */     JSONArray arr = (JSONArray)JSON.toJSON(list);
/*      */     
/*  215 */     for (int i = 0; i < arr.size(); i++) {
/*      */       
/*  217 */       JSONObject t = arr.getJSONObject(i);
/*      */       
/*  219 */       QueryWrapper<Record> countWrapper = new QueryWrapper();
/*      */       
/*  221 */       countWrapper.eq("merchant", member.getMerchant());
/*  222 */       countWrapper.eq("code", t.getString("code"));
/*  223 */       countWrapper.eq("uid", uid);
/*  224 */       countWrapper.eq("state", state);
/*  225 */       countWrapper.eq("sale", sale);
/*  226 */       countWrapper.groupBy("code");
/*      */       
/*  228 */       Project project = (Project)this.projectService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", member.getMerchant())).eq("bar_code", t.getString("code")));
/*      */       
/*  230 */       int count = this.recordService.count((Wrapper)countWrapper);
/*      */       
/*  232 */       t.put("total", Integer.valueOf(count));
/*      */       
/*  234 */       if (project != null) {
/*  235 */         t.put("project_state", project.getState());
/*      */       }
/*      */     } 
/*      */ 
/*      */ 
/*      */     
/*  241 */     return success(arr);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @GetMapping({"{id}"})
/*      */   public R selectOne(@PathVariable Serializable id) {
/*  254 */     return success(this.recordService.getById(id));
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @GetMapping({"/count"})
/*      */   public R selectCount(String merchant, String uid) {
/*  267 */     int examine_num = this.recordService.count((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("uid", uid)).eq("state", "审核中"));
/*  268 */     int adopt_num = this.recordService.count((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("uid", uid)).eq("state", "已通过"));
/*  269 */     int failed_num = this.recordService.count((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("uid", uid)).eq("state", "未通过"));
/*      */ 
/*      */     
/*  272 */     int sum = adopt_num + failed_num;
/*      */     
/*  274 */     double d1 = adopt_num * 1.0D;
/*  275 */     double d2 = sum * 1.0D;
/*  276 */     NumberFormat percentInstance = NumberFormat.getPercentInstance();
/*      */     
/*  278 */     percentInstance.setMinimumFractionDigits(2);
/*      */     
/*  280 */     String credit = "";
/*      */     
/*  282 */     if (sum != 0 && failed_num != 0 && failed_num != 0) {
/*  283 */       credit = percentInstance.format(d1 / d2);
/*      */     } else {
/*  285 */       credit = "计算中";
/*      */     } 
/*      */     
/*  288 */     JSONObject data = new JSONObject();
/*      */     
/*  290 */     data.put("credit", credit);
/*  291 */     data.put("examine_num", Integer.valueOf(examine_num));
/*  292 */     data.put("adopt_num", Integer.valueOf(adopt_num));
/*  293 */     data.put("failed_num", Integer.valueOf(failed_num));
/*      */     
/*  295 */     return success(data);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @PostMapping({"/add"})
/*      */   public R insert(@RequestBody String jsonStr) {
/*  307 */     Calendar cal = Calendar.getInstance();
/*      */     
/*  309 */     DateFormat stateTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
/*      */     
/*  311 */     DateFormat oidTime = new SimpleDateFormat("yyyyMMddHHmmss");
/*      */     
/*  313 */     DateFormat dayTime = new SimpleDateFormat("yyyy-MM-dd");
/*      */     
/*  315 */     String start = dayTime.format(cal.getTime()) + " 00:00:00";
/*  316 */     String end = dayTime.format(cal.getTime()) + " 23:59:59";
/*      */     
/*  318 */     Random random = new Random();
/*      */     
/*  320 */     int i = random.nextInt(1000) + 1000;
/*      */     
/*  322 */     String oid = oidTime.format(cal.getTime()) + i;
/*      */     
/*  324 */     JSONObject o = JSONObject.parseObject(jsonStr);
/*      */     
/*  326 */     Member member = (Member)this.memberService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", o.getString("merchant"))).eq("uid", o.getString("uid")));
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */     
/*  333 */     if (member == null) {
/*  334 */       return success(Boolean.valueOf(false)).setCode(101L).setMsg("非法请求,系统拦截");
/*      */     }
/*      */     
/*  337 */     if (member.getState().equals("已冻结")) {
/*  338 */       return success(Boolean.valueOf(false)).setCode(101L).setMsg("账号违规,已被封禁");
/*      */     }
/*      */     
/*  341 */     if (member.getPhone() == null || member.getPhone().equals("")) {
/*  342 */       return success(Boolean.valueOf(false)).setCode(102L).setMsg("请先绑定手机号");
/*      */     }
/*      */ 
/*      */     
/*  346 */     Grade grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("sort", member.getPartner())).eq("merchant", o.getString("merchant")));
/*      */     
/*  348 */     int count = this.recordService.count((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", o.getString("merchant"))).eq("uid", o.getString("uid")))
/*  349 */         .between("create_time", start, end));
/*      */     
/*  351 */     log.info("用户：{}，已录：{}", member.getUid(), Integer.valueOf(count));
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */     
/*  378 */     int cid = o.getIntValue("cid");
/*      */     
/*  380 */     Project project = (Project)this.projectService.getById(Integer.valueOf(cid));
/*      */     
/*  382 */     if (project.getState().equals("不回收")) {
/*  383 */       return success(Boolean.valueOf(false)).setCode(101L).setMsg("录入失败,该项目目前不回收");
/*      */     }
/*      */     
/*  386 */     if (project.getState().equals("待审核")) {
/*  387 */       return success(Boolean.valueOf(false)).setCode(101L).setMsg("录入失败,该项目目前不回收");
/*      */     }
/*      */     
/*  390 */     if (project.getPattern() != null && !project.getPattern().equals("")) {
/*      */       
/*  392 */       boolean matches = o.getString("qr_code").matches(project.getPattern());
/*      */       
/*  394 */       if (!matches) {
/*  395 */         return success(Boolean.valueOf(false)).setCode(101L).setMsg("录入失败,录入二维码格式有误");
/*      */       }
/*      */     } 
/*      */     
/*  399 */     if (project.getChecking().booleanValue() && o.getString("check_code").equals("")) {
/*  400 */       return success(Boolean.valueOf(false)).setCode(101L).setMsg("录入失败,败验证码不能为空");
/*      */     }
/*      */     
/*  403 */     Record old = (Record)this.recordService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("code", o.getString("code"))).eq("qr_code", o.getString("qr_code")));
/*      */     
/*  405 */     if (old != null) {
/*  406 */       return success(Boolean.valueOf(false)).setCode(101L).setMsg("录入失败,二维码已被回收");
/*      */     }
/*      */ 
/*      */     
/*  410 */     DecimalFormat format = new DecimalFormat("0.00");
/*      */     
/*  412 */     format.setRoundingMode(RoundingMode.DOWN);
/*      */     
/*  414 */     Double n_points = Double.valueOf(project.getPoints().doubleValue() * grade.getGain().doubleValue());
/*      */     
/*  416 */     String str = format.format(n_points);
/*  417 */     n_points = Double.valueOf(Double.parseDouble(str));
/*      */     
/*  419 */     this.projectService.getById(Integer.valueOf(cid));
/*      */     
/*  421 */     Record record = new Record();
/*  422 */     record.setId(Integer.valueOf(0));
/*  423 */     record.setMerchant(o.getString("merchant"));
/*  424 */     record.setOid(oid);
/*  425 */     record.setName(project.getName());
/*  426 */     record.setImage(project.getImage());
/*  427 */     record.setPoints(n_points);
/*  428 */     record.setUid(o.getString("uid"));
/*  429 */     record.setCid(Integer.valueOf(o.getIntValue("cid")));
/*  430 */     record.setCode(o.getString("code"));
/*  431 */     record.setQrCode(o.getString("qr_code"));
/*  432 */     record.setCheckCode(o.getString("check_code"));
/*  433 */     record.setState("审核中");
/*  434 */     record.setSale(Integer.valueOf(0));
/*  435 */     record.setCreateTime(stateTime.format(cal.getTime()));
/*      */     
/*  437 */     boolean save = this.recordService.save(record);
/*      */     
/*  439 */     return success(Boolean.valueOf(save));
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/mixed_input"})
/*      */   public R mixed_input(String merchant, String qr_code, String uid) {
/*  453 */     Member member = (Member)this.memberService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("uid", uid));
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */     
/*  460 */     if (member == null) {
/*  461 */       return success(Boolean.valueOf(false)).setCode(101L).setMsg("非法请求,系统拦截");
/*      */     }
/*      */     
/*  464 */     if (member.getState().equals("已冻结")) {
/*  465 */       return success(Boolean.valueOf(false)).setCode(101L).setMsg("账号违规,已被封禁");
/*      */     }
/*      */     
/*  468 */     if (member.getPhone() == null || member.getPhone().equals("")) {
/*  469 */       return success(Boolean.valueOf(false)).setCode(102L).setMsg("请先绑定手机号");
/*      */     }
/*      */     
/*  472 */     Calendar cal = Calendar.getInstance();
/*      */     
/*  474 */     DateFormat stateTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
/*      */     
/*  476 */     DateFormat oidTime = new SimpleDateFormat("yyyyMMddHHmmss");
/*      */     
/*  478 */     DateFormat dayTime = new SimpleDateFormat("yyyy-MM-dd");
/*      */     
/*  480 */     String start = dayTime.format(cal.getTime()) + " 00:00:00";
/*  481 */     String end = dayTime.format(cal.getTime()) + " 23:59:59";
/*      */ 
/*      */     
/*  484 */     Grade grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("sort", member.getPartner())).eq("merchant", merchant));
/*      */     
/*  486 */     Random random = new Random();
/*      */     
/*  488 */     int rand = random.nextInt(1000) + 1000;
/*      */     
/*  490 */     String oid = oidTime.format(cal.getTime()) + rand;
/*      */     
/*  492 */     List<Project> list = this.projectService.list((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("mixed", Boolean.valueOf(true))).ne("state", "不回收"));
/*      */     
/*  494 */     for (int i = 0; i < list.size(); i++) {
/*      */       
/*  496 */       if (((Project)list.get(i)).getPattern() != null) {
/*      */ 
/*      */ 
/*      */         
/*  500 */         boolean matches = qr_code.matches(((Project)list.get(i)).getPattern());
/*      */         
/*  502 */         if (matches) {
/*      */           
/*  504 */           Record old = (Record)this.recordService.getOne((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("code", ((Project)list.get(i)).getBarCode())).eq("qr_code", qr_code));
/*      */           
/*  506 */           if (old != null) {
/*  507 */             return failed("录入失败,二维码已被回收");
/*      */           }
/*      */           
/*  510 */           DecimalFormat format = new DecimalFormat("0.00");
/*      */           
/*  512 */           format.setRoundingMode(RoundingMode.DOWN);
/*      */           
/*  514 */           Double n_points = Double.valueOf(((Project)list.get(i)).getPoints().doubleValue() * grade.getGain().doubleValue());
/*      */           
/*  516 */           String str = format.format(n_points);
/*  517 */           n_points = Double.valueOf(Double.parseDouble(str));
/*      */           
/*  519 */           Record record = new Record();
/*  520 */           record.setId(Integer.valueOf(0));
/*  521 */           record.setMerchant(merchant);
/*  522 */           record.setOid(oid);
/*  523 */           record.setName(((Project)list.get(i)).getName());
/*  524 */           record.setImage(((Project)list.get(i)).getImage());
/*  525 */           record.setPoints(n_points);
/*  526 */           record.setUid(uid);
/*  527 */           record.setCid(Integer.valueOf(((Project)list.get(i)).getCid()));
/*  528 */           record.setCode(((Project)list.get(i)).getBarCode());
/*  529 */           record.setQrCode(qr_code);
/*  530 */           record.setCheckCode("");
/*  531 */           record.setState("审核中");
/*  532 */           record.setSale(Integer.valueOf(0));
/*  533 */           record.setCreateTime(stateTime.format(cal.getTime()));
/*      */           
/*  535 */           boolean save = this.recordService.save(record);
/*      */           
/*  537 */           return success(null);
/*      */         } 
/*      */       } 
/*      */     } 
/*      */ 
/*      */     
/*  543 */     return failed("录入失败,未找到回收项目");
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/updateState"})
/*      */   public R updateState(String oid, String state) {
/*  554 */     Record record = (Record)this.recordService.getOne((Wrapper)(new QueryWrapper()).eq("oid", oid));
/*      */     
/*  556 */     if (record == null || !record.getState().equals("审核中") || record.getSale().intValue() != 1) {
/*  557 */       return success("操作失败").setCode(101L);
/*      */     }
/*      */     
/*  560 */     if (state.equals("已通过")) {
/*      */       
/*  562 */       Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", record.getUid()));
/*      */       
/*  564 */       double sum = record.getPoints().doubleValue() + member.getPoints().doubleValue();
/*      */       
/*  566 */       log.info("用户UID：{}，当前积分：{}", record.getUid(), Double.valueOf(sum));
/*      */       
/*  568 */       member.setPoints(Double.valueOf(sum));
/*      */       
/*  570 */       this.memberService.saveOrUpdate(member);
/*      */       
/*  572 */       Settlement settlement = new Settlement();
/*  573 */       settlement.setId(Integer.valueOf(0));
/*  574 */       settlement.setUid(member.getUid());
/*  575 */       settlement.setType("回收结算");
/*  576 */       settlement.setNotes("卖出：" + record.getName());
/*  577 */       settlement.setTotal(record.getPoints());
/*      */       
/*  579 */       this.settlementService.save(settlement);
/*      */ 
/*      */       
/*  582 */       Member t_member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", member.getMid()));
/*      */       
/*  584 */       if (t_member != null) {
/*      */ 
/*      */         
/*  587 */         Grade t_grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("sort", t_member.getPartner())).eq("merchant", record.getMerchant()));
/*      */         
/*  589 */         Project project = (Project)this.projectService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("bar_code", record.getCode())).eq("merchant", record.getMerchant()));
/*      */         
/*  591 */         Double t_points = Double.valueOf(project.getPoints().doubleValue() * t_grade.getGain().doubleValue());
/*      */         
/*  593 */         Double rebate = Double.valueOf(t_points.doubleValue() - record.getPoints().doubleValue());
/*      */         
/*  595 */         if (rebate.doubleValue() >= 0.01D) {
/*  596 */           t_member.setPoints(Double.valueOf(t_member.getPoints().doubleValue() + rebate.doubleValue()));
/*      */           
/*  598 */           Settlement t_settlement = new Settlement();
/*  599 */           t_settlement.setId(Integer.valueOf(0));
/*  600 */           t_settlement.setSid(member.getUid());
/*  601 */           t_settlement.setUid(t_member.getUid());
/*  602 */           t_settlement.setType("卖货提成");
/*  603 */           t_settlement.setNotes("来自：下级" + member.getUid() + "卖出:" + record.getName());
/*  604 */           t_settlement.setTotal(rebate);
/*      */           
/*  606 */           this.settlementService.save(t_settlement);
/*      */           
/*  608 */           this.memberService.saveOrUpdate(t_member);
/*      */         } 
/*      */       } 
/*      */     } 
/*      */ 
/*      */     
/*  614 */     record.setState(state);
/*      */     
/*  616 */     this.recordService.saveOrUpdate(record);
/*      */     
/*  618 */     return success(Boolean.valueOf(true));
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @PutMapping
/*      */   public R update(@RequestBody Record record) {
/*  629 */     return success(Boolean.valueOf(this.recordService.updateById(record)));
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @PostMapping({"/stock_all"})
/*      */   public R stock_all(@RequestParam("idList") List<Long> idList, HttpSession session) {
/*  643 */     User user = (User)session.getAttribute("user");
/*      */     
/*  645 */     Calendar cal = Calendar.getInstance();
/*      */     
/*  647 */     DateFormat stateTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
/*      */     
/*  649 */     int success = 0;
/*      */     
/*  651 */     for (int i = 0; i < idList.size(); i++) {
/*      */       
/*  653 */       Record record = (Record)this.recordService.getById(idList.get(i));
/*      */       
/*  655 */       Stock stock = new Stock();
/*      */       
/*  657 */       stock.setId(Integer.valueOf(0));
/*  658 */       stock.setMerchant(user.getMerchant());
/*  659 */       stock.setOid(record.getOid());
/*  660 */       stock.setUid(record.getUid());
/*  661 */       stock.setCid(record.getCid());
/*  662 */       stock.setName(record.getName());
/*  663 */       stock.setImage(record.getImage());
/*  664 */       stock.setPoints(record.getPoints());
/*  665 */       stock.setCode(record.getCode());
/*  666 */       stock.setQrCode(record.getQrCode());
/*  667 */       stock.setCheckCode(record.getCheckCode());
/*  668 */       stock.setState("已入库");
/*  669 */       stock.setCreateTime(stateTime.format(cal.getTime()));
/*      */       
/*  671 */       boolean save = this.stockService.save(stock);
/*      */       
/*  673 */       if (save) {
/*  674 */         success++;
/*      */       }
/*      */     } 
/*      */     
/*  678 */     JSONObject data = new JSONObject();
/*      */     
/*  680 */     data.put("total", Integer.valueOf(idList.size()));
/*  681 */     data.put("success", Integer.valueOf(success));
/*  682 */     data.put("fail", Integer.valueOf(idList.size() - success));
/*      */     
/*  684 */     return success(data);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/export"})
/*      */   public void createTxt(String bar_code, @RequestParam(required = false, defaultValue = "") String uid, @RequestParam(required = false, defaultValue = "1") Integer total, @RequestParam(required = false, defaultValue = "desc") String sort, HttpServletResponse response, HttpSession session) throws Exception {
/*  700 */     Calendar cal = Calendar.getInstance();
/*      */     
/*  702 */     SimpleDateFormat fileData = new SimpleDateFormat("yyyyMMddHHmmss");
/*      */     
/*  704 */     DateFormat createTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
/*      */     
/*  706 */     User user = (User)session.getAttribute("user");
/*      */ 
/*      */     
/*  709 */     Project project = (Project)this.projectService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("bar_code", bar_code)).eq("merchant", user.getMerchant()));
/*      */     
/*  711 */     if (project == null) {
/*  712 */       PrintWriter out = null;
/*      */       
/*      */       try {
/*  715 */         response.setContentType("application/json;charset=UTF-8");
/*  716 */         response.setHeader("Cache-Control", "no-cache");
/*  717 */         out = response.getWriter();
/*  718 */         out.print(JSON.toJSONString(failed("项目不存在")));
/*  719 */       } catch (Exception e) {
/*  720 */         log.error("接口返回异常", e);
/*      */       } finally {
/*  722 */         if (out != null) {
/*  723 */           out.flush();
/*  724 */           out.close();
/*      */         } 
/*      */       } 
/*      */     } 
/*      */     
/*  729 */     QueryWrapper<Record> recordQueryWrapper = new QueryWrapper();
/*      */     
/*  731 */     recordQueryWrapper.eq("code", bar_code);
/*  732 */     recordQueryWrapper.eq("sale", Integer.valueOf(1));
/*  733 */     recordQueryWrapper.eq("state", "审核中");
/*  734 */     recordQueryWrapper.eq("export_state", Integer.valueOf(0));
/*  735 */     recordQueryWrapper.eq("merchant", user.getMerchant());
/*  736 */     if (!uid.equals("")) {
/*  737 */       recordQueryWrapper.eq("uid", uid);
/*      */     }
/*      */     
/*  740 */     int count = this.recordService.count((Wrapper)recordQueryWrapper);
/*      */     
/*  742 */     if (total.intValue() > count) {
/*  743 */       PrintWriter out = null;
/*      */       
/*      */       try {
/*  746 */         response.setContentType("application/json;charset=UTF-8");
/*  747 */         response.setHeader("Cache-Control", "no-cache");
/*  748 */         out = response.getWriter();
/*  749 */         out.print(JSON.toJSONString(failed("导出数量大于库存数量：" + count)));
/*  750 */       } catch (Exception e) {
/*  751 */         log.error("接口返回异常", e);
/*      */       } finally {
/*  753 */         if (out != null) {
/*  754 */           out.flush();
/*  755 */           out.close();
/*      */         } 
/*      */       } 
/*      */     } 
/*      */ 
/*      */     
/*  761 */     if (!sort.equals("desc")) {
/*  762 */       recordQueryWrapper.orderByAsc("create_time");
/*      */     } else {
/*  764 */       recordQueryWrapper.orderByDesc("create_time");
/*      */     } 
/*      */     
/*  767 */     recordQueryWrapper.last("LIMIT " + total);
/*      */     
/*  769 */     List<Record> list = this.recordService.list((Wrapper)recordQueryWrapper);
/*      */     
/*  771 */     if (total.intValue() > list.size()) {
/*      */       
/*  773 */       PrintWriter out = null;
/*      */       
/*      */       try {
/*  776 */         response.setContentType("application/json;charset=UTF-8");
/*  777 */         response.setHeader("Cache-Control", "no-cache");
/*  778 */         out = response.getWriter();
/*  779 */         out.print(JSON.toJSONString(failed("导出数量大于库存数量：" + list.size())));
/*  780 */       } catch (Exception e) {
/*  781 */         log.error("接口返回异常", e);
/*      */       } finally {
/*  783 */         if (out != null) {
/*  784 */           out.flush();
/*  785 */           out.close();
/*      */         } 
/*      */       } 
/*      */     } else {
/*      */       
/*  790 */       Double points = Double.valueOf(0.0D);
/*      */       
/*  792 */       List<Record> export_list = list.subList(0, total.intValue());
/*      */       
/*  794 */       UpdateWrapper<Record> updateWrapper = new UpdateWrapper();
/*  795 */       updateWrapper.set("export_state", Integer.valueOf(1));
/*      */       
/*  797 */       updateWrapper.eq("merchant", user.getMerchant());
/*  798 */       updateWrapper.eq("code", bar_code);
/*  799 */       updateWrapper.eq("state", "审核中");
/*  800 */       updateWrapper.eq("export_state", Integer.valueOf(0));
/*  801 */       updateWrapper.eq("sale", Integer.valueOf(1));
/*  802 */       if (!uid.equals("")) {
/*  803 */         updateWrapper.eq("uid", uid);
/*      */       }
/*  805 */       if (!sort.equals("desc")) {
/*  806 */         updateWrapper.orderByAsc("create_time");
/*      */       } else {
/*  808 */         updateWrapper.orderByDesc("create_time");
/*      */       } 
/*  810 */       updateWrapper.last("LIMIT " + total);
/*      */       
/*  812 */       this.recordService.update((Wrapper)updateWrapper);
/*      */       
/*  814 */       response.setContentType("text/plain;");
/*      */       
/*  816 */       String fileName = fileData.format(cal.getTime());
/*      */       
/*  818 */       response.setHeader("Content-Disposition", "attachment; filename=" + fileName + ".txt");
/*      */       
/*  820 */       BufferedOutputStream buff = null;
/*      */       
/*  822 */       StringBuffer write = new StringBuffer();
/*      */       
/*  824 */       String enter = "\r\n";
/*      */       
/*  826 */       ServletOutputStream outSTr = null;
/*      */       
/*      */       try {
/*  829 */         outSTr = response.getOutputStream();
/*  830 */         buff = new BufferedOutputStream((OutputStream)outSTr);
/*      */         
/*  832 */         if (export_list.size() > 0) {
/*      */           
/*  834 */           for (int i = 0; i < export_list.size(); i++) {
/*      */             
/*  836 */             points = Double.valueOf(points.doubleValue() + ((Record)export_list.get(i)).getPoints().doubleValue());
/*      */             
/*  838 */             if (((Record)export_list.get(i)).getCheckCode().length() > 0) {
/*  839 */               write.append(((Record)export_list.get(i)).getQrCode() + "-" + ((Record)export_list.get(i)).getCheckCode());
/*      */             } else {
/*  841 */               write.append(((Record)export_list.get(i)).getQrCode());
/*      */             } 
/*      */             
/*  844 */             write.append(enter);
/*      */           } 
/*      */         } else {
/*      */           
/*  848 */           write.append("卡密库存不足");
/*      */         } 
/*      */         
/*  851 */         write.append(enter);
/*      */         
/*  853 */         DecimalFormat format = new DecimalFormat("0.00");
/*      */         
/*  855 */         format.setRoundingMode(RoundingMode.DOWN);
/*      */         
/*  857 */         StringBuilder sb = new StringBuilder();
/*      */         
/*  859 */         sb.append("[导出信息]").append(enter);
/*  860 */         sb.append("条码:" + bar_code).append(enter);
/*  861 */         sb.append("名称:" + project.getName()).append(enter);
/*  862 */         sb.append("数量:" + total).append(enter);
/*  863 */         sb.append("积分:" + format.format(points)).append(enter);
/*  864 */         sb.append("时间:" + createTime.format(cal.getTime()));
/*      */         
/*  866 */         write.append(sb);
/*      */         
/*  868 */         buff.write(write.toString().getBytes("UTF-8"));
/*  869 */         buff.flush();
/*  870 */         buff.close();
/*  871 */       } catch (Exception e) {
/*  872 */         e.printStackTrace();
/*      */       } finally {
/*      */         try {
/*  875 */           buff.close();
/*  876 */           outSTr.close();
/*  877 */         } catch (Exception e) {
/*  878 */           e.printStackTrace();
/*      */         } 
/*      */       } 
/*      */     } 
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @PostMapping({"/effective"})
/*      */   public R effective(@RequestParam("idList") List<Long> idList, HttpSession session) {
/*  894 */     User user = (User)session.getAttribute("user");
/*      */     
/*  896 */     if (idList.size() == 0) {
/*  897 */       return success(Boolean.valueOf(false)).setMsg("未选中数据").setCode(101L);
/*      */     }
/*      */ 
/*      */     
/*  901 */     List<Record> list = this.recordService.listByIds(idList);
/*      */ 
/*      */ 
/*      */     
/*  905 */     Map<String, String> notes_map = new HashMap<>();
/*      */ 
/*      */     
/*  908 */     Map<String, List<Record>> groupedByUid = (Map<String, List<Record>>)list.stream().collect(Collectors.groupingBy(Record::getUid));
/*      */ 
/*      */     
/*  911 */     groupedByUid.forEach((uid, items) -> {
/*      */           System.out.println("用户" + uid + ":");
/*      */ 
/*      */           
/*      */           List<Record> items1 = items;
/*      */ 
/*      */           
/*      */           Map<String, List<Record>> groupedByCode = (Map<String, List<Record>>)items1.stream().distinct().collect(Collectors.groupingBy(Record::getCode));
/*      */ 
/*      */           
/*      */           System.out.println("录入了：" + groupedByCode.size() + "个品类");
/*      */ 
/*      */           
/*      */           StringBuilder sb = new StringBuilder();
/*      */ 
/*      */           
/*      */           //groupedByCode.forEach(());
/*      */           
/*      */           notes_map.put(uid, sb.substring(0, sb.length() - 1));
/*      */         });
/*      */     
/*  932 */     ListIterator<Record> iterator = list.listIterator();
/*      */     
/*  934 */     Lock look = new ReentrantLock();
/*      */     
/*  936 */     ConcurrentHashMap<String, BigDecimal> map_body = new ConcurrentHashMap<>();
/*  937 */     ConcurrentHashMap<String, Record> map_record = new ConcurrentHashMap<>();
/*      */     
/*  939 */     int total = list.size() / 20;
/*      */     
/*  941 */     if (total < 1) {
/*  942 */       total = 1;
/*      */     }
/*      */     
/*  945 */     CountDownLatch countDownLatch = new CountDownLatch(total);
/*      */     
/*  947 */     synchronized (iterator) {
/*      */       
/*  949 */       for (int i = 0; i < total; i++) {
/*      */         
/*  951 */         (new Thread(() -> {
/*      */               while (iterator.hasNext()) {
/*      */                 Record record = iterator.next();
/*      */                 
/*      */                 record.setState("已通过");
/*      */                 
/*      */                 this.recordService.saveOrUpdate(record);
/*      */                 
/*      */                 look.lock();
/*      */                 
/*      */                 if (map_body.containsKey(record.getUid())) {
/*      */                   BigDecimal value = (BigDecimal)map_body.get(record.getUid());
/*      */                   
/*      */                   BigDecimal sum = value.add(new BigDecimal(record.getPoints().toString()));
/*      */                   
/*      */                   map_body.put(record.getUid(), sum);
/*      */                 } else {
/*      */                   map_body.put(record.getUid(), new BigDecimal(record.getPoints().toString()));
/*      */                   
/*      */                   map_record.put(record.getUid(), record);
/*      */                 } 
/*      */                 
/*      */                 look.unlock();
/*      */               } 
/*      */               countDownLatch.countDown();
/*  976 */             },String.valueOf(i))).start();
/*      */       } 
/*      */     } 
/*      */ 
/*      */     
/*      */     try {
/*  982 */       countDownLatch.await();
/*  983 */     } catch (InterruptedException e) {
/*  984 */       e.printStackTrace();
/*      */     } 
/*      */     
/*  987 */     for (Map.Entry<String, BigDecimal> entry : map_body.entrySet()) {
/*      */       
/*  989 */       Member member = (Member)this.memberService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("uid", entry.getKey()));
/*      */       
/*  991 */       if (member != null) {
/*      */         
/*  993 */         double sum = ((BigDecimal)entry.getValue()).doubleValue() + member.getPoints().doubleValue();
/*      */         
/*  995 */         log.info("用户UID：{}，当前积分：{}", member.getUid(), Double.valueOf(sum));
/*      */         
/*  997 */         member.setPoints(Double.valueOf(sum));
/*      */         
/*  999 */         this.memberService.saveOrUpdate(member);
/*      */         
/* 1001 */         Settlement settlement = new Settlement();
/* 1002 */         settlement.setId(Integer.valueOf(0));
/* 1003 */         settlement.setUid(member.getUid());
/* 1004 */         settlement.setType("回收结算");
/* 1005 */         settlement.setNotes("卖出：" + (String)notes_map.get(member.getUid()));
/* 1006 */         settlement.setTotal(Double.valueOf(((BigDecimal)entry.getValue()).doubleValue()));
/*      */         
/* 1008 */         this.settlementService.save(settlement);
/*      */         
/* 1010 */         Member t_member = (Member)this.memberService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("uid", member.getMid()));
/*      */         
/* 1012 */         if (t_member != null) {
/*      */           
/* 1014 */           Grade t_grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("sort", t_member.getPartner())).eq("merchant", user.getMerchant()));
/*      */           
/* 1016 */           BigDecimal rebate = ((BigDecimal)entry.getValue()).multiply(new BigDecimal(t_grade.getPresent().toString()));
/*      */           
/* 1018 */           if (rebate.doubleValue() >= 0.01D) {
/*      */             
/* 1020 */             t_member.setPoints(Double.valueOf(t_member.getPoints().doubleValue() + rebate.doubleValue()));
/*      */             
/* 1022 */             Settlement t_settlement = new Settlement();
/* 1023 */             t_settlement.setId(Integer.valueOf(0));
/* 1024 */             t_settlement.setSid(member.getUid());
/* 1025 */             t_settlement.setUid(t_member.getUid());
/* 1026 */             t_settlement.setType("卖货提成");
/* 1027 */             t_settlement.setNotes("源自:下级" + member.getUid() + "卖出:" + (String)notes_map.get(member.getUid()));
/* 1028 */             t_settlement.setTotal(Double.valueOf(rebate.doubleValue()));
/*      */             
/* 1030 */             this.settlementService.save(t_settlement);
/*      */             
/* 1032 */             this.memberService.saveOrUpdate(t_member);
/*      */           } 
/*      */         } 
/*      */       } 
/*      */     } 
/*      */ 
/*      */     
/* 1039 */     return success(Boolean.valueOf(true));
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @PostMapping({"/invalid"})
/*      */   public R invalid(@RequestParam("idList") List<Long> idList, HttpSession session) {
/* 1051 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1053 */     log.info("执行批量无效:{}", idList);
/*      */     
/* 1055 */     if (idList.size() == 0) {
/* 1056 */       return success(Boolean.valueOf(false)).setMsg("未选中数据").setCode(101L);
/*      */     }
/*      */     
/* 1059 */     UpdateWrapper<Record> updateWrapper = new UpdateWrapper();
/*      */     
/* 1061 */     updateWrapper.set("state", "未通过");
/*      */     
/* 1063 */     updateWrapper.eq("merchant", user.getMerchant());
/*      */     
/* 1065 */     updateWrapper.eq("state", "审核中");
/*      */     
/* 1067 */     updateWrapper.in("id", idList);
/*      */     
/* 1069 */     boolean update = this.recordService.update((Wrapper)updateWrapper);
/*      */     
/* 1071 */     return success(Boolean.valueOf(update));
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @PostMapping({"/import_code"})
/*      */   public R import_code(String bar_code, Integer total, Integer state, @RequestParam("codeList") List<String> codeList, HttpSession session) {
/* 1081 */     log.info("code：{},total：{}，size：{}，state：{}", new Object[] { bar_code, total, Integer.valueOf(codeList.size()), state });
/*      */     
/* 1083 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1085 */     if (user == null) {
/* 1086 */       return success(Boolean.valueOf(false));
/*      */     }
/*      */     
/* 1089 */     if (total.intValue() != codeList.size()) {
/* 1090 */       return success(Boolean.valueOf(false)).setMsg("导入数量校验失败");
/*      */     }
/*      */ 
/*      */     
/* 1094 */     if (state.equals(Integer.valueOf(0))) {
/*      */       
/* 1096 */       UpdateWrapper<Record> updateWrapper = new UpdateWrapper();
/* 1097 */       updateWrapper.set("state", "未通过");
/* 1098 */       updateWrapper.eq("code", bar_code);
/* 1099 */       updateWrapper.eq("state", "审核中");
/* 1100 */       updateWrapper.in("qr_code", codeList);
/*      */       
/* 1102 */       boolean update = this.recordService.update((Wrapper)updateWrapper);
/*      */       
/* 1104 */       return success(Boolean.valueOf(update));
/*      */     } 
/*      */ 
/*      */ 
/*      */     
/* 1109 */     QueryWrapper<Record> queryWrapper = new QueryWrapper();
/* 1110 */     queryWrapper.eq("code", bar_code);
/* 1111 */     queryWrapper.eq("state", "审核中");
/* 1112 */     queryWrapper.in("qr_code", codeList);
/*      */     
/* 1114 */     List<Record> list = this.recordService.list((Wrapper)queryWrapper);
/*      */     
/* 1116 */     ListIterator<Record> iterator = list.listIterator();
/*      */     
/* 1118 */     Lock look = new ReentrantLock();
/*      */     
/* 1120 */     ConcurrentHashMap<String, BigDecimal> map_body = new ConcurrentHashMap<>();
/* 1121 */     ConcurrentHashMap<String, Record> map_record = new ConcurrentHashMap<>();
/*      */     
/* 1123 */     int count = codeList.size() / 30;
/*      */     
/* 1125 */     if (count > 35) {
/* 1126 */       count = 35;
/*      */     }
/*      */     
/* 1129 */     if (count < 1) {
/* 1130 */       count = 1;
/*      */     }
/*      */     
/* 1133 */     System.out.println("创建线程：" + total + "条");
/*      */     
/* 1135 */     CountDownLatch countDownLatch = new CountDownLatch(count);
/*      */     
/* 1137 */     synchronized (iterator) {
/*      */       
/* 1139 */       for (int i = 0; i < count; i++) {
/*      */         
/* 1141 */         (new Thread(() -> {
/*      */               while (iterator.hasNext()) {
/*      */                 Record record = iterator.next();
/*      */ 
/*      */                 
/*      */                 if (record != null) {
/*      */                   if (state.equals(Integer.valueOf(0))) {
/*      */                     record.setState("未通过");
/*      */                     
/*      */                     this.recordService.saveOrUpdate(record);
/*      */                     
/*      */                     continue;
/*      */                   } 
/*      */                   
/*      */                   record.setState("已通过");
/*      */                   
/*      */                   this.recordService.saveOrUpdate(record);
/*      */                   
/*      */                   look.lock();
/*      */                   
/*      */                   if (map_body.containsKey(record.getUid())) {
/*      */                     BigDecimal value = (BigDecimal)map_body.get(record.getUid());
/*      */                     
/*      */                     BigDecimal sum = value.add(new BigDecimal(record.getPoints().toString()));
/*      */                     
/*      */                     map_body.put(record.getUid(), sum);
/*      */                   } else {
/*      */                     map_body.put(record.getUid(), new BigDecimal(record.getPoints().toString()));
/*      */                     
/*      */                     map_record.put(record.getUid(), record);
/*      */                   } 
/*      */                   
/*      */                   look.unlock();
/*      */                 } 
/*      */               } 
/*      */               
/*      */               countDownLatch.countDown();
/* 1178 */             },String.valueOf(i))).start();
/*      */       } 
/*      */     } 
/*      */ 
/*      */     
/*      */     try {
/* 1184 */       countDownLatch.await();
/* 1185 */     } catch (InterruptedException e) {
/* 1186 */       e.printStackTrace();
/*      */     } 
/*      */     
/* 1189 */     for (Map.Entry<String, BigDecimal> entry : map_body.entrySet()) {
/*      */       
/* 1191 */       Member member = (Member)this.memberService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("uid", entry.getKey()));
/*      */       
/* 1193 */       Record record = map_record.get(entry.getKey());
/*      */       
/* 1195 */       if (member != null) {
/*      */         
/* 1197 */         double sum = ((BigDecimal)entry.getValue()).doubleValue() + member.getPoints().doubleValue();
/*      */         
/* 1199 */         log.info("用户UID：{}，当前积分：{}", member.getUid(), Double.valueOf(sum));
/*      */         
/* 1201 */         member.setPoints(Double.valueOf(sum));
/*      */         
/* 1203 */         this.memberService.saveOrUpdate(member);
/*      */         
/* 1205 */         Settlement settlement = new Settlement();
/* 1206 */         settlement.setId(Integer.valueOf(0));
/* 1207 */         settlement.setUid(member.getUid());
/* 1208 */         settlement.setType("回收结算");
/* 1209 */         settlement.setNotes("卖出:" + record.getName() + ",单价:" + record.getPoints() + "元");
/* 1210 */         settlement.setTotal(Double.valueOf(((BigDecimal)entry.getValue()).doubleValue()));
/*      */         
/* 1212 */         this.settlementService.save(settlement);
/*      */         
/* 1214 */         Member t_member = (Member)this.memberService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("uid", member.getMid()));
/*      */         
/* 1216 */         if (t_member != null) {
/*      */           
/* 1218 */           Grade t_grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("sort", t_member.getPartner())).eq("merchant", user.getMerchant()));
/*      */           
/* 1220 */           BigDecimal rebate = ((BigDecimal)entry.getValue()).multiply(new BigDecimal(t_grade.getPresent().toString()));
/*      */           
/* 1222 */           if (rebate.doubleValue() >= 0.01D) {
/*      */             
/* 1224 */             t_member.setPoints(Double.valueOf(t_member.getPoints().doubleValue() + rebate.doubleValue()));
/*      */             
/* 1226 */             Settlement t_settlement = new Settlement();
/* 1227 */             t_settlement.setId(Integer.valueOf(0));
/* 1228 */             t_settlement.setSid(member.getUid());
/* 1229 */             t_settlement.setUid(t_member.getUid());
/* 1230 */             t_settlement.setType("卖货提成");
/* 1231 */             t_settlement.setNotes("源自:下级" + member.getUid() + "卖出:" + record.getName());
/* 1232 */             t_settlement.setTotal(Double.valueOf(rebate.doubleValue()));
/*      */             
/* 1234 */             this.settlementService.save(t_settlement);
/*      */             
/* 1236 */             this.memberService.saveOrUpdate(t_member);
/*      */           } 
/*      */         } 
/*      */       } 
/*      */     } 
/*      */ 
/*      */ 
/*      */ 
/*      */     
/* 1245 */     return success(Boolean.valueOf(true));
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @PostMapping({"/verify"})
/*      */   public R verify(String barCode, Double passRate, Long base, HttpSession session) {
/* 1257 */     long startTime = System.nanoTime();
/*      */     
/* 1259 */     log.info("自动核销计划：编码：{},通过率：{},核销基数：{}", new Object[] { barCode, passRate, base });
/*      */     
/* 1261 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1263 */     if (user == null) {
/* 1264 */       return success(Boolean.valueOf(false)).setMsg("登录失效");
/*      */     }
/*      */     
/* 1267 */     if (passRate.doubleValue() > 1.0D) {
/* 1268 */       return success(Boolean.valueOf(false)).setMsg("通过率参数异常");
/*      */     }
/*      */     
/* 1271 */     if (barCode == null) {
/* 1272 */       return success(Boolean.valueOf(false)).setMsg("核销项目为空");
/*      */     }
/*      */     
/* 1275 */     QueryWrapper<Record> queryWrapper = (QueryWrapper<Record>)((QueryWrapper)((QueryWrapper)((QueryWrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("code", barCode)).eq("sale", Integer.valueOf(1))).eq("export_state", Integer.valueOf(1))).eq("state", "审核中")).groupBy("uid");
/*      */     
/* 1277 */     queryWrapper.select(new String[] { "COUNT(*) as 'size',uid" });
/*      */     
/* 1279 */     List<Map<String, Object>> maps = this.recordService.listMaps((Wrapper)queryWrapper);
/*      */     
/* 1281 */     List<Record> recordList = new ArrayList<>();
/*      */     
/* 1283 */     for (Map<String, Object> map : maps) {
/*      */       
/* 1285 */       Long size = (Long)map.get("size");
/* 1286 */       String uid = (String)map.get("uid");
/*      */       
/* 1288 */       if (size.longValue() > base.longValue()) {
/*      */         
/* 1290 */         Integer integer = Integer.valueOf((int)(size.longValue() * (1.0D - passRate.doubleValue())));
/* 1291 */         List<Integer> randomList = randomList(size.intValue(), integer.intValue());
/*      */         
/* 1293 */         List<Record> list1 = this.recordService.list((Wrapper)((QueryWrapper)((QueryWrapper)((QueryWrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("code", barCode)).eq("uid", uid)).eq("sale", Integer.valueOf(1))).eq("export_state", Integer.valueOf(1))).eq("state", "审核中"));
/*      */         
/* 1295 */         randomList.forEach(i -> {
/*      */               Record r = list1.get(i.intValue());
/*      */ 
/*      */               
/*      */               r.setState("未通过");
/*      */ 
/*      */               
/*      */               recordList.add(r);
/*      */             });
/*      */       } 
/*      */     } 
/*      */     
/* 1307 */     log.info("不通过总数：{}", Integer.valueOf(recordList.size()));
/*      */     
/* 1309 */     this.recordService.updateBatchById(recordList);
/*      */     
/* 1311 */     List<Record> list = this.recordService.list((Wrapper)((QueryWrapper)((QueryWrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("code", barCode)).eq("sale", Integer.valueOf(1))).eq("export_state", Integer.valueOf(1))).eq("state", "审核中"));
/*      */     
/* 1313 */     if (list.size() == 0) {
/* 1314 */       return failed("库存数量为零");
/*      */     }
/* 1316 */     System.out.println("处理：" + list.size());
/*      */ 
/*      */     
/* 1319 */     ListIterator<Record> iterator = list.listIterator();
/*      */     
/* 1321 */     Lock look = new ReentrantLock();
/*      */     
/* 1323 */     ConcurrentHashMap<String, BigDecimal> map_body = new ConcurrentHashMap<>();
/* 1324 */     ConcurrentHashMap<String, Record> map_record = new ConcurrentHashMap<>();
/*      */     
/* 1326 */     int total = list.size() / 20;
/*      */     
/* 1328 */     if (total > 50) {
/* 1329 */       total = 50;
/*      */     }
/*      */     
/* 1332 */     if (total < 1) {
/* 1333 */       total = 1;
/*      */     }
/*      */     
/* 1336 */     System.out.println("创建线程：" + total + "条");
/*      */ 
/*      */ 
/*      */     
/* 1340 */     List<Record> complete_list = new ArrayList<>();
/*      */ 
/*      */     
/* 1343 */     List<Record> abnormal_list = new ArrayList<>();
/*      */     
/* 1345 */     CountDownLatch countDownLatch = new CountDownLatch(total);
/*      */     
/* 1347 */     synchronized (iterator) {
/*      */       
/* 1349 */       for (int i = 0; i < total; i++) {
/*      */         
/* 1351 */         (new Thread(() -> {
/*      */               while (iterator.hasNext()) {
/*      */                 Record record = iterator.next();
/*      */ 
/*      */                 
/*      */                 try {
/*      */                   look.lock();
/*      */                   
/*      */                   if (map_body.containsKey(record.getUid())) {
/*      */                     BigDecimal value = (BigDecimal)map_body.get(record.getUid());
/*      */                     
/*      */                     BigDecimal sum = value.add(new BigDecimal(record.getPoints().toString()));
/*      */                     
/*      */                     map_body.put(record.getUid(), sum);
/*      */                   } else {
/*      */                     map_body.put(record.getUid(), new BigDecimal(record.getPoints().toString()));
/*      */                     
/*      */                     map_record.put(record.getUid(), record);
/*      */                   } 
/*      */                   
/*      */                   record.setState("已通过");
/*      */                   
/*      */                   complete_list.add(record);
/*      */                   
/*      */                   look.unlock();
/* 1376 */                 } catch (Exception e) {
/*      */                   System.out.println("核销出现异常：" + e.getMessage());
/*      */                   
/*      */                   log.info("核销出现异常：{},{}", record, record.getOid());
/*      */                   
/*      */                   abnormal_list.add(record);
/*      */                   
/*      */                   look.unlock();
/*      */                 } 
/*      */               } 
/*      */               
/*      */               countDownLatch.countDown();
/* 1388 */             },String.valueOf(i))).start();
/*      */       } 
/*      */     } 
/*      */ 
/*      */     
/*      */     try {
/* 1394 */       countDownLatch.await();
/* 1395 */     } catch (InterruptedException e) {
/* 1396 */       e.printStackTrace();
/*      */     } 
/*      */ 
/*      */     
/* 1400 */     this.recordService.updateBatchById(complete_list);
/*      */ 
/*      */ 
/*      */     
/* 1404 */     for (Map.Entry<String, BigDecimal> entry : map_body.entrySet()) {
/*      */       
/* 1406 */       Member member = (Member)this.memberService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("uid", entry.getKey()));
/*      */       
/* 1408 */       Record record = map_record.get(entry.getKey());
/*      */       
/* 1410 */       if (member != null) {
/*      */         
/* 1412 */         double sum = ((BigDecimal)entry.getValue()).doubleValue() + member.getPoints().doubleValue();
/*      */         
/* 1414 */         log.info("用户UID：{}，当前积分：{}", member.getUid(), Double.valueOf(sum));
/*      */         
/* 1416 */         member.setPoints(Double.valueOf(sum));
/*      */         
/* 1418 */         this.memberService.saveOrUpdate(member);
/*      */         
/* 1420 */         Settlement settlement = new Settlement();
/* 1421 */         settlement.setId(Integer.valueOf(0));
/* 1422 */         settlement.setUid(member.getUid());
/* 1423 */         settlement.setType("回收结算");
/* 1424 */         settlement.setNotes("卖出:" + record.getName() + ",单价:" + record.getPoints() + "元");
/* 1425 */         settlement.setTotal(Double.valueOf(((BigDecimal)entry.getValue()).doubleValue()));
/*      */         
/* 1427 */         this.settlementService.save(settlement);
/*      */         
/* 1429 */         Member t_member = (Member)this.memberService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("uid", member.getMid()));
/*      */         
/* 1431 */         if (t_member != null) {
/*      */           
/* 1433 */           Grade t_grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("sort", t_member.getPartner())).eq("merchant", user.getMerchant()));
/*      */           
/* 1435 */           BigDecimal rebate = ((BigDecimal)entry.getValue()).multiply(new BigDecimal(t_grade.getPresent().toString()));
/*      */           
/* 1437 */           if (rebate.doubleValue() >= 0.01D) {
/*      */             
/* 1439 */             t_member.setPoints(Double.valueOf(t_member.getPoints().doubleValue() + rebate.doubleValue()));
/*      */             
/* 1441 */             Settlement t_settlement = new Settlement();
/* 1442 */             t_settlement.setId(Integer.valueOf(0));
/* 1443 */             t_settlement.setSid(member.getUid());
/* 1444 */             t_settlement.setUid(t_member.getUid());
/* 1445 */             t_settlement.setType("卖货提成");
/* 1446 */             t_settlement.setNotes("源自:下级" + member.getUid() + "卖出:" + record.getName());
/* 1447 */             t_settlement.setTotal(Double.valueOf(rebate.doubleValue()));
/*      */             
/* 1449 */             this.settlementService.save(t_settlement);
/*      */             
/* 1451 */             this.memberService.saveOrUpdate(t_member);
/*      */           } 
/*      */         } 
/*      */       } 
/*      */     } 
/*      */ 
/*      */     
/* 1458 */     long endTime = System.nanoTime();
/*      */     
/* 1460 */     long executionTime = endTime - startTime;
/*      */     
/* 1462 */     long ms = executionTime / 1000000000L;
/*      */     
/* 1464 */     return success(Boolean.valueOf(true)).setMsg("耗时：" + ms + "秒");
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @DeleteMapping({"/del"})
/*      */   public R delete(@RequestParam("idList") List<Long> idList) {
/* 1478 */     if (idList.size() == 0) {
/* 1479 */       return success(Boolean.valueOf(false)).setMsg("未选中数据").setCode(101L);
/*      */     }
/*      */     
/* 1482 */     return success(Boolean.valueOf(this.recordService.removeByIds(idList)));
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   private static List<Integer> randomList(int size, int total) {
/* 1489 */     List<Integer> list = new ArrayList<>();
/*      */     
/* 1491 */     while (list.size() < total) {
/* 1492 */       int randomInt = RandomUtil.randomInt(0, size);
/* 1493 */       if (!list.contains(Integer.valueOf(randomInt))) {
/* 1494 */         list.add(Integer.valueOf(randomInt));
/*      */       }
/*      */     } 
/* 1497 */     return list;
/*      */   }
/*      */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\RecordController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */